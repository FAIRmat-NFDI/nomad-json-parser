#
# Copyright The NOMAD Authors.
#
# This file is part of NOMAD. See https://nomad-lab.eu for further info.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import ast
from typing import (
    TYPE_CHECKING,
)

import jmespath
from nomad.datamodel import EntryArchive
from nomad.parsing import MatchingParser
from pyld import jsonld

if TYPE_CHECKING:
    from nomad.datamodel.datamodel import (
        EntryArchive,
    )

import json
import re
import time
from copy import deepcopy

from nomad.datamodel import ClientContext, EntryArchive
from nomad.datamodel.metainfo.annotations import (
    Rules,
)
from nomad.datamodel.results import ELN, Results
from nomad.search import (
    MetadataPagination,
    MetadataRequired,
    search,
)
from nomad.utils.json_transformer import Transformer
from nomad_material_processing.utils import create_archive

from nomad_json_parser.schema_packages.jsonimport import (
    JsonMapper,
    MainMapper,
    MappedJson,
    MapperRule,
    MatchKey,
    RepeatKey,
    RepeatPath,
    RuleCondition,
    SubSectionMapper,
    createrulesjson,
    get_class,
)


def create_rules(subsection, key, logger):
    rules = []
    if 'rules' in subsection:
        for rulekey in subsection['rules'].keys():
            rule = subsection['rules'][rulekey]
            rulesection = MapperRule()
            try:
                if not ('source' in rule.keys() and 'target' in rule.keys()):
                    logger.error(
                        f'Rule {rulekey} from Subsection {key} is '
                        'missing source or target key.'
                    )
                rulesection.name = rulekey
                rulesection.source = rule['source']
                rulesection.target = rule['target']
                if 'default_value' in rule.keys():
                    rulesection.default_value = rule['default_value']
                if 'use_rule' in rule.keys():
                    rulesection.use_rule = rule['use_rule']
                if 'conditions' in rule.keys():
                    condlist = []
                    for condition in rule['conditions']:
                        conditionssection = RuleCondition()
                        condname = next(iter(condition))
                        conditionssection.name = condname
                        conditionssection.regex_path = condition[condname]['regex_path']
                        conditionssection.regex_pattern = condition[condname][
                            'regex_pattern'
                        ]
                        condlist.append(conditionssection)
                    rulesection.conditions = condlist
                if 'target_type' in rule.keys():
                    rulesection.target_type = rule['target_type']
                if 'match_key' in rule.keys():
                    all_keys = []
                    for m_key in range(10):
                        str_m_key = f'match_key{m_key}'.strip('0')
                        if str_m_key not in rule.keys():
                            break
                        matchkey = MatchKey()
                        matchkey.name = f'Match for part {m_key}.'
                        keys_list = []
                        for s in rule[str_m_key]:
                            repkey = RepeatKey()
                            repkey.name = str(s)
                            keys_list.append(repkey)
                        matchkey.match_keys = keys_list
                        all_keys.append(matchkey)
                    rulesection.match_key = all_keys
            except AttributeError:
                rulesection.name = f'{rulekey}_to_{rule}'
                rulesection.source = rulekey
                rulesection.target = rule
            rules.append(rulesection)
    else:
        logger.warning(
            f'Rules section is missing from Subsection {key}. \
                No mapping will be done.'
        )
    return rules


def create_mainmapping(subsection, key, logger, archive):  # noqa: PLR0912, PLR0915
    sectionclass = MainMapper()
    if (
        'main_key' in subsection
        or 'is_archive' in subsection
        or 'repeats' in subsection
        or 'repeat_paths' in subsection
    ):
        logger.error(
            'Main section of json mapper should not contain \
                main_key or is_archive or repeats or repeat_paths.'
        )
    sectionclass.name = key
    try:
        sectionclass.path_to_schema = subsection['schema']
    except KeyError:
        logger.error(f'schema is missing from Subsection {key}.')
    sectionclass.rules = create_rules(subsection, key, logger)
    sectionclass.normalize(archive, logger)
    return sectionclass


def create_submapping(subsection, key, logger, archive):  # noqa: PLR0912, PLR0915
    sectionclass = SubSectionMapper()
    try:
        sectionclass.main_key = subsection['main_key']
    except KeyError:
        logger.error(f'main_key is missing from Subsection {key}.')
    if 'is_archive' in subsection:
        sectionclass.is_archive = subsection['is_archive']
    if 'repeats' in subsection:
        sectionclass.repeats = subsection['repeats']
        if 'repeat_paths' in subsection:
            repeat_paths = []
            for path in subsection['repeat_paths']:
                repeat = RepeatPath()
                repeat.name = path
                repeat_paths.append(repeat)
            sectionclass.repeat_paths = repeat_paths
            if 'repeat_keys' in subsection:
                keys_list = []
                for s in subsection['repeat_keys']:
                    repkey = RepeatKey()
                    repkey.name = str(s)
                    keys_list.append(repkey)
                sectionclass.repeat_keys = keys_list
    if 'repeat_paths' in subsection and 'repeats' not in subsection:
        logger.warning('repeat_paths found but not repeats, ignoring repeat_paths.')
    if 'subsections' in subsection:
        subsections = []
        for subkey in subsection['subsections'].keys():
            logger.info(subkey, subsection['subsections'][subkey])
            subsectionclass = create_submapping(
                subsection['subsections'][subkey], subkey, logger, archive
            )  # noqa: E501
            subsections.append(subsectionclass)
        sectionclass.subsection_mappings = subsections
    sectionclass.name = key
    try:
        sectionclass.path_to_schema = subsection['schema']
    except KeyError:
        logger.error(f'schema is missing from Subsection {key}.')
    sectionclass.rules = create_rules(subsection, key, logger)
    sectionclass.normalize(archive, logger)
    return sectionclass


def create_sectionclass(jsonfile, logger, archive):  # noqa: PLR0912, PLR0915
    main_found = False
    subsections = []
    for key in jsonfile.keys():
        if key in {'$json_mapper_class_key', '$json_mapper_version'}:
            continue
        subsection = jsonfile[key]
        if 'is_main' in subsection and subsection['is_main'] == 'True':
            if not main_found:
                main_found = True
                main_mapping = create_mainmapping(subsection, key, logger, archive)
            else:
                logger.error('is_main can only be in one Subsection.')
        else:
            sectionclass = create_submapping(subsection, key, logger, archive)
            subsections.append(sectionclass)
    return main_mapping, subsections


class JsonMapperParser(MatchingParser):
    def set_entrydata_definition(self):
        self.entrydata_definition = JsonMapper

    def parse(self, mainfile: str, archive: EntryArchive, logger) -> None:  # noqa: PLR0912, PLR0915
        self.set_entrydata_definition()
        data_file_with_path = mainfile.rsplit('raw/', maxsplit=1)[-1]
        entry = self.entrydata_definition()
        entry.mapper_file = data_file_with_path

        if not archive.results:
            archive.results = Results(eln=ELN())
        if not archive.results.eln:
            archive.results.eln = ELN()
        archive.results.eln.sections = ['JsonMapper']

        if entry.mapper_file:
            with archive.m_context.raw_file(entry.mapper_file, 'r') as file:
                jsonfile = json.load(file)

            try:
                entry.mapper_key = jsonfile['$json_mapper_class_key']
                archive.results.eln.lab_ids = [entry.mapper_key]
                if '$json_mapper_version' in jsonfile.keys():
                    entry.mapper_version = jsonfile['$json_mapper_version']
                else:
                    entry.mapper_version = 1
                archive.results.eln.tags = [entry.mapper_version]
            except KeyError:
                logger.error(
                    'Missing keys for jsonmapper file ($json_mapper_class_key).'
                )
            logger.info(
                'Starting search for already existing mappers with\
                      same key and version.'
            )
            if not isinstance(archive.m_context, ClientContext):
                search_result = search(
                    owner='all',
                    query={
                        'data.mapper_key#nomad_json_parser.schema_packages.jsonimport.JsonMapper': entry.mapper_key,  # noqa: E501
                        'data.mapper_version#nomad_json_parser.schema_packages.jsonimport.JsonMapper': entry.mapper_version,  # noqa: E501
                    },
                    user_id=archive.metadata.main_author.user_id,
                )
                if len(search_result.data) > 1:
                    logger.error(
                        'At least one mapper with the same key and\
                              version has been found.'
                    )

            entry.main_mapping, entry.subsection_mappings = create_sectionclass(
                jsonfile, logger, archive
            )
            if entry.main_mapping is None:
                logger.error('No main mapping found.')

        archive.data = entry
        archive.metadata.entry_name = (
            f'JsonMapper_{entry.mapper_key}_v{entry.mapper_version}'
        )


def correcttypes(transformed_sub, subclass_rules):
    for rule in subclass_rules:
        if rule['target'] in transformed_sub.keys() and 'target_type' in rule:
            if rule['target_type'] == 'array':
                if not isinstance(transformed_sub[rule['target']], list):
                    transformed_sub[rule['target']] = [transformed_sub[rule['target']]]
            elif rule['target_type'] == 'float':
                try:
                    transformed_sub[rule['target']] = float(
                        transformed_sub[rule['target']]
                    )
                except ValueError:
                    transformed_sub[rule['target']] = 0
    return transformed_sub


def transform_subclass(  # noqa: PLR0913
    subclass_mapping,
    logger,
    jsonfile,
    archive,
    archive_list,
    repeatpath,
    data_file_with_path,
):
    if repeatpath == '' and 'repeat_paths' in subclass_mapping:
        repeatpath = subclass_mapping['repeat_paths'][0]['name']
    subclass = get_class(subclass_mapping['path_to_schema'], logger)()
    subrules = {
        'sub_transformation': Rules(
            **json.loads(createrulesjson(subclass_mapping['rules']))
        )
    }
    subtransformer = Transformer(subrules)
    transformed_sub = subtransformer.transform(jsonfile, 'sub_transformation')

    tempunits = transformed_sub.pop('tempunits', None)
    logger.info(subclass)

    transformed_sub = correcttypes(transformed_sub, subclass_mapping['rules'])

    logger.info(transformed_sub)
    subclass.m_update_from_dict(transformed_sub)
    if tempunits:
        from pint import UnitRegistry

        ureg = UnitRegistry(autoconvert_offset_to_baseunit=True)
        for unitkey in tempunits.keys():
            try:
                setattr(
                    subclass,
                    unitkey,
                    subclass[unitkey].magnitude * ureg(tempunits[unitkey]),
                )
            except KeyError:
                pass

    if 'subsection_mappings' in subclass_mapping:
        for i in range(len(subclass_mapping['subsection_mappings'])):
            subsectionmap = subclass_mapping['subsection_mappings'][i]
            if not repeatpath == '':
                for rule in subsectionmap['rules']:
                    rule['source'] = '.'.join([repeatpath, rule['source']])
            subsubclass = transform_subclass(
                subsectionmap,
                logger,
                jsonfile,
                archive,
                archive_list,
                repeatpath,
                data_file_with_path,
            )
            if 'is_archive' in subsectionmap.keys() and subsectionmap['is_archive']:
                sub_ref = create_archive(
                    subsubclass,
                    archive,
                    f'{data_file_with_path.rsplit("/", maxsplit=1)[0]}/{subsubclass.name}.archive.json',
                )
                archive_list.append(sub_ref)
                setattr(subclass, subsectionmap['main_key'], sub_ref)
            elif 'repeats' in subsectionmap.keys() and subsectionmap['repeats']:
                subclass[subsectionmap['main_key']].append(subsubclass)
            else:
                setattr(subclass, subsectionmap['main_key'], subsubclass)
    return subclass


def checkforvalidkey(path, backjson, submap):  # noqa: PLR0911, PLR0912
    backkey = path['name'].split('*')[1].strip('.')
    if backkey:
        backjson = jmespath.compile(backkey).search(backjson)
    #     for j in range(len(backkey.split('.'))):
    #         try:
    #             backjson = backjson[backkey.split('.')[j]]
    #         except (KeyError, TypeError, AttributeError):
    #             return False
    if not isinstance(backjson, dict):
        return False
    if 'repeat_keys' in submap:
        for key in submap['repeat_keys']:
            rulejson = dict(backjson)
            if key['name'].startswith('{'):
                matching = ast.literal_eval(key['name'])
                for k in matching.keys():
                    try:
                        if not re.match(
                            matching[k], jmespath.compile(k).search(rulejson)
                        ):
                            return False
                    except (KeyError, TypeError):
                        return False
            else:
                try:
                    rulejson = jmespath.compile(key['name']).search(rulejson)
                except (KeyError, TypeError):
                    return False
    else:
        for rule in submap['rules']:
            rulejson = dict(backjson)
            for rulekey in rule['source'].split('.'):
                try:
                    rulejson = rulejson[rulekey]
                except (KeyError, TypeError):
                    return False
    return True


def appendnewrepeatpath(path, key, newrepeatpath):
    frontkey = path['name'].split('*')[0].strip('.')
    backkey = path['name'].split('*')[1].strip('.')
    newpath = deepcopy(path)
    newpath['name'] = key
    if frontkey:
        newpath['name'] = frontkey + '.' + newpath['name']
    if backkey:
        newpath['name'] = newpath['name'] + '.' + backkey
    newrepeatpath.append(newpath)


def resolve_dynamical_mapper_paths(mapper, jsonfile):  # noqa: PLR0912
    if 'subsection_mappings' in mapper.keys():
        newsubmappings = []
        for i in range(len(mapper['subsection_mappings'])):
            submap = mapper['subsection_mappings'][i]
            if 'repeat_paths' in submap and len(submap['repeat_paths']) > 0:
                newrepeatpath = []
                for path in submap['repeat_paths']:
                    if '*' in path['name']:
                        frontkey = path['name'].split('*')[0].strip('.')
                        iteratedjson = dict(jsonfile)
                        if frontkey:
                            iteratedjson = jmespath.compile(frontkey).search(
                                iteratedjson
                            )
                        for key in iteratedjson.keys():
                            if isinstance(iteratedjson[key], list):
                                for k in range(len(iteratedjson[key])):
                                    try:
                                        backjson = dict(iteratedjson[key][k])
                                    except ValueError:
                                        continue
                                    keyisvalid = checkforvalidkey(
                                        path, backjson, submap
                                    )
                                    if keyisvalid:
                                        appendnewrepeatpath(
                                            path, f'{key}[{k}]', newrepeatpath
                                        )
                            else:
                                try:
                                    backjson = dict(iteratedjson[key])
                                except ValueError:
                                    continue
                                keyisvalid = checkforvalidkey(path, backjson, submap)
                                if keyisvalid:
                                    appendnewrepeatpath(path, key, newrepeatpath)
                    else:
                        newrepeatpath.append(path)
                submap['repeat_paths'] = newrepeatpath
                if len(newrepeatpath) == 0:
                    continue
            newsubmappings.append(submap)
        mapper['subsection_mappings'] = newsubmappings
    return mapper


def checkforvalidrulematch(backjson, matchrule):
    if not isinstance(backjson, dict):
        return False
    for key in matchrule['match_keys']:
        rulejson = dict(backjson)
        if key['name'].startswith('{'):
            matching = ast.literal_eval(key['name'])
            for k in matching.keys():
                try:
                    if not re.match(matching[k], jmespath.compile(k).search(rulejson)):
                        return False
                except (KeyError, TypeError):
                    return False
        else:
            try:
                rulejson = jmespath.compile(key['name']).search(rulejson)
            except (KeyError, TypeError):
                return False
    return True


def ruleblock_resolve(ruleblock, jsonfile, logger):
    newruleblock = []
    for rule in ruleblock:
        newrule = deepcopy(rule)
        for m_key in range(10):
            if (
                '*' in newrule['source']
                and 'match_key' in newrule.keys()
                and len(newrule['match_key']) > m_key
            ):
                logger.warning(newrule, m_key)
                newsourcepath = ''
                frontkey = newrule['source'].split('*')[0].strip('.')
                iteratedjson = dict(jsonfile)
                if frontkey:
                    iteratedjson = jmespath.compile(frontkey).search(iteratedjson)
                for key in iteratedjson.keys():
                    if isinstance(iteratedjson[key], list):
                        for k in range(len(iteratedjson[key])):
                            try:
                                backjson = dict(iteratedjson[key][k])
                            except ValueError:
                                continue
                            keyisvalid = checkforvalidrulematch(
                                backjson, newrule['match_key'][m_key]
                            )
                            if keyisvalid:
                                if newsourcepath:
                                    logger.warning(
                                        f'Found more than one match for rule {rule["name"]} in main mapping. Taking the last match.'  # noqa: E501
                                    )
                                newsourcepath = newrule['source'].replace(
                                    '*', f'{key}[{k}]', 1
                                )
                    else:
                        try:
                            backjson = dict(iteratedjson[key])
                        except ValueError:
                            continue
                        keyisvalid = checkforvalidrulematch(
                            backjson, newrule['match_key'][m_key]
                        )
                        if keyisvalid:
                            if newsourcepath:
                                logger.warning(
                                    f'Found more than one match for rule {newrule["name"]} in main mapping. Taking the last match.'  # noqa: E501
                                )
                            newsourcepath = newrule['source'].replace('*', key, 1)

                if newsourcepath:
                    newrule['source'] = newsourcepath
                logger.warning(newrule, m_key)
        newruleblock.append(newrule)
    return newruleblock


def resolve_dynamical_rules(mapper, mapname, jsonfile, logger):  # noqa: PLR0912
    if mapname == 'main_mapping':
        ruleblock = mapper['main_mapping']['rules']
        mapper['main_mapping']['rules'] = ruleblock_resolve(ruleblock, jsonfile, logger)
    else:
        ruleblock = mapper['rules']
        mapper['rules'] = ruleblock_resolve(ruleblock, jsonfile, logger)
    if (
        'subsection_mappings' in mapper.keys()
        and len(mapper['subsection_mappings']) > 0
    ):
        for i in range(len(mapper['subsection_mappings'])):
            mapper['subsection_mappings'][i] = resolve_dynamical_rules(
                mapper['subsection_mappings'][i], 'subsection', jsonfile, logger
            )
    return mapper


def expand_block(mapperblock, parentpath=''):
    newsubmappings = []
    for i in range(len(mapperblock)):
        submap = mapperblock[i]
        if 'repeat_paths' in submap and len(submap['repeat_paths']) > 0:
            for path in submap['repeat_paths']:
                addpath = '.'.join([parentpath, path['name']]).strip('.')
                repeatmap = deepcopy(submap)
                repeatmap['name'] = addpath + '__$' + submap['name']
                repeatmap['repeat_paths'] = [RepeatPath(name=addpath)]
                for rule in repeatmap['rules']:
                    rule['source'] = '.'.join([addpath, rule['source']])
                if 'subsection_mappings' in repeatmap.keys():
                    newblock = repeatmap['subsection_mappings']
                    repeatmap['subsection_mappings'] = expand_block(newblock, addpath)
                newsubmappings.append(repeatmap)
        else:
            for rule in submap['rules']:
                rule['source'] = '.'.join([parentpath, rule['source']]).strip('.')
            if 'subsection_mappings' in submap.keys():
                newblock = submap['subsection_mappings']
                submap['subsection_mappings'] = expand_block(newblock, parentpath)
            newsubmappings.append(submap)
    return newsubmappings


def expand_mapper(mapper):
    if 'subsection_mappings' in mapper.keys():
        mapperblock = mapper['subsection_mappings']
        mapper['subsection_mappings'] = expand_block(mapperblock)
    return mapper


def map_with_nesting(
    mapper, mapname, logger, archive, jsonfile, archive_list, data_file_with_path
):  # noqa: PLR0912, PLR0913
    mapkey = ''
    repeat_path = False
    logger.info(mapname)
    if 'subsection_mappings' in mapper.keys():
        for i in range(len(mapper['subsection_mappings'])):
            submap = mapper['subsection_mappings'][i]
            if submap['name'] == mapname:
                mapkey = submap['main_key']
                if 'repeat_paths' in submap:
                    repeat_path = True
                subclass = transform_subclass(
                    submap,
                    logger,
                    jsonfile,
                    archive,
                    archive_list,
                    '',
                    data_file_with_path,
                )
    mapkey_parent = mapkey + '.'
    if mapkey == '':
        subclass = transform_subclass(
            mapper['main_mapping'],
            logger,
            jsonfile,
            archive,
            archive_list,
            '',
            data_file_with_path,
        )
    if 'subsection_mappings' in mapper.keys():
        for i in range(len(mapper['subsection_mappings'])):
            submap = mapper['subsection_mappings'][i]
            shortened_mainkey = submap['main_key'].removeprefix(mapkey_parent)
            if mapkey == '':
                mapkey_parent = ''
            if (
                submap['main_key'].startswith(mapkey_parent)
                and '.' not in shortened_mainkey
            ):
                if (
                    repeat_path
                    and not mapname.split('__$')[0] == submap['name'].split('__$')[0]
                ):
                    continue
                subsubclass = map_with_nesting(
                    mapper,
                    submap['name'],
                    logger,
                    archive,
                    jsonfile,
                    archive_list,
                    data_file_with_path,
                )
                if 'is_archive' in submap.keys() and submap['is_archive']:
                    sub_ref = create_archive(
                        subsubclass,
                        archive,
                        f'{data_file_with_path.rsplit("/", maxsplit=1)[0]}/{subsubclass.name}.archive.json',
                    )
                    archive_list.append(sub_ref)
                    setattr(subclass, shortened_mainkey, sub_ref)
                elif 'repeats' in submap.keys() and submap['repeats']:
                    subclass[shortened_mainkey].append(subsubclass)
                else:
                    setattr(subclass, shortened_mainkey, subsubclass)
    return subclass


class MappedJsonParser(MatchingParser):
    def set_entrydata_definition(self):
        self.entrydata_definition = MappedJson

    def parse(self, mainfile: str, archive: EntryArchive, logger) -> None:  # noqa: PLR0912, PLR0915
        self.set_entrydata_definition()
        data_file = mainfile.rsplit('/', maxsplit=1)[-1]
        data_file_with_path = mainfile.rsplit('raw/', maxsplit=1)[-1]
        entry = self.entrydata_definition()
        entry.json_file = data_file_with_path

        if entry.json_file:
            with archive.m_context.raw_file(entry.json_file, 'r') as file:
                jsonfile = json.load(file)

            try:
                entry.mapper_key = jsonfile['$mapped_json_class_key']
                if '$mapped_json_version' in jsonfile.keys():
                    entry.mapper_version = jsonfile['$mapped_json_version']
            except KeyError:
                logger.error(
                    'Missing keys for mappedjson file ($mapped_json_class_key).'
                )

        logger.info('Starting search for mapper with same key.')
        if not isinstance(archive.m_context, ClientContext):
            query = {
                'data.mapper_key#nomad_json_parser.schema_packages.jsonimport.JsonMapper': entry.mapper_key,  # noqa: E501
            }
            if entry.mapper_version:
                logger.info(
                    f'Searching for mapper with version {entry.mapper_version}.'
                )
                query[
                    'data.mapper_version#nomad_json_parser.schema_packages.jsonimport.JsonMapper'
                ] = entry.mapper_version
            else:
                logger.info('Searching for mapper with latest version.')
            numberofretries = 5
            for count in range(numberofretries):
                logger.info(f'Starting search loop {count}.')
                search_result = search(
                    owner='all',
                    query=query,
                    required=MetadataRequired(
                        include=['data*', 'upload_id', 'entry_id']
                    ),
                    pagination=MetadataPagination(
                        page_size=1,
                        order='desc',
                        order_by='data.mapper_version#nomad_json_parser.schema_packages.jsonimport.JsonMapper',
                    ),
                    user_id=archive.metadata.main_author.user_id,
                )
                if len(search_result.data) > 1:
                    logger.error(
                        'Found more than one suitable mapper. This can not be.'
                    )
                elif len(search_result.data) == 0:
                    logger.warning('Found no matching mapper.')
                elif len(search_result.data) == 1:
                    mapper_result = search_result.data[0]
                    upload_id = mapper_result['upload_id']
                    entry_id = mapper_result['entry_id']
                    entry.mapper_reference = (
                        f'../uploads/{upload_id}/archive/{entry_id}#data'
                    )
                    mapper = mapper_result['data']
                    break
                time.sleep(5)
            else:
                logger.error('No mapper was found.')

            logger.info(mapper)

            mapper = resolve_dynamical_mapper_paths(mapper, jsonfile)

            logger.info(mapper)
            mapper_expanded = expand_mapper(mapper)

            logger.info(mapper_expanded)

            mapper_expanded = resolve_dynamical_rules(
                mapper_expanded, 'main_mapping', jsonfile, logger
            )

            logger.info(mapper_expanded)
            archive_list = []
            mainclass = map_with_nesting(
                mapper_expanded,
                mapper_expanded['main_mapping']['name'],
                logger,
                archive,
                jsonfile,
                archive_list,
                data_file_with_path,
            )

            main_ref = create_archive(
                mainclass,
                archive,
                f'{data_file_with_path.rsplit("/", maxsplit=1)[0]}/{mainclass.name}.archive.json',
            )
            archive_list.append(main_ref)
            archive_list.reverse()  # put main entry as first
            entry.generated_entries = archive_list

        archive.data = entry
        archive.metadata.entry_name = (
            f'{data_file}_MappedJson_{entry.mapper_key}_v{entry.mapper_version}'
        )


class ROCrateParser(MatchingParser):
    def __init__(
        self,
        json_matching_key: str | None = None,
        json_matching_re: str = r'.*',
        **kwargs,
    ) -> None:
        super().__init__(**kwargs)
        self.json_matching_key = json_matching_key
        self.json_matching_re = re.compile(json_matching_re)

    def is_mainfile(
        self,
        filename: str,
        mime: str,
        buffer: bytes,
        decoded_buffer: str,
        compression: str | None = None,
    ) -> bool:
        # First do standard matching
        if not super().is_mainfile(filename, mime, buffer, decoded_buffer, compression):
            return False

        # Additional custom logic to ensure this is the ONLY parser that matches
        # For example, check that this is specifically a PLD file

        # Read the file to make sure it's really a PLD file
        with open(filename) as f:
            content = f.read()
        # Only proceed if it's definitely a PLD file
        if self.json_matching_re.search(content) is None:
            return False

        return True

    def parse(self, mainfile: str, archive: EntryArchive, logger) -> None:  # noqa: PLR0912, PLR0915
        data_file_with_path = mainfile.rsplit('raw/', maxsplit=1)[-1]

        attrs = vars(self)
        for key, value in attrs.items():
            logger.error(f'{key}: {value}')

        with archive.m_context.raw_file(data_file_with_path, 'r') as file:
            data = json.load(file)

        # fix file pathes (TODO: local pathes would fix the issue)
        for j in range(len(data['@graph'])):
            if data['@graph'][j]['@type'] == 'File':
                data = json.loads(
                    json.dumps(data).replace(
                        data['@graph'][j]['@id'],
                        data['@graph'][j]['@id'].replace(
                            './',
                            './' + data_file_with_path.strip('ro-crate-metadata.json'),
                        ),
                    )
                )

        # fix base id
        expandeddata = jsonld.expand(
            data,
            options={'base': 'file://'},
            # this will replace "./" with "file:///"
        )

        frame = {
            '@context': [
                'https://w3id.org/ro/crate/1.2/context',
                {
                    '@base': 'http://example.org/base/',
                    '@vocab': 'http://example.org/base/',
                },
            ],
            '@id': 'file:./',
            '@embed': '@always',
        }

        frameddata = jsonld.frame(expandeddata, frame)

        compact_context = {
            '@context': [
                'https://w3id.org/ro/crate/1.2/context',
                {
                    '@base': 'file:./',  # will replace "file:///" with "./"
                    'type': '@type',  # optional for clean keywords
                    'id': '@id',  # optional for clean keywords
                    'base': '@base',
                },
            ]
        }

        compacteddata = jsonld.compact(
            frameddata, compact_context
        )  # save the framed data to file

        compacteddatawithkey = {
            '$mapped_json_class_key': self.json_matching_key,
            **compacteddata,
        }

        filename = data_file_with_path.replace(
            'ro-crate-metadata.json', 'frameddata.json'
        )

        with archive.m_context.raw_file(filename, 'w') as outfile:
            json.dump(compacteddatawithkey, outfile)

        if self.json_matching_key != 'default_key':
            toparse = MappedJsonParser(json_file=filename)
            toparse.parse(filename, archive, logger)

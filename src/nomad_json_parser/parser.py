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

from typing import (
    TYPE_CHECKING,
)

from nomad.datamodel import EntryArchive
from nomad.parsing import MatchingParser

if TYPE_CHECKING:
    from nomad.datamodel.datamodel import (
        EntryArchive,
    )

import json

from nomad.datamodel import ClientContext, EntryArchive
from nomad.datamodel.metainfo.annotations import (
    Rules,
)
from nomad.datamodel.results import ELN, Results
from nomad.search import search
from nomad.utils.json_transformer import Transformer
from nomad_material_processing.utils import create_archive

from nomad_json_parser.jsonimport import (
    JsonMapper,
    MainMapper,
    MappedJson,
    MapperRule,
    RuleCondition,
    SubSectionMapper,
    createrulesjson,
    get_class,
)


class JsonMapperParser(MatchingParser):
    def set_entrydata_definition(self):
        self.entrydata_definition = JsonMapper

    def parse(self, mainfile: str, archive: EntryArchive, logger) -> None:  # noqa: PLR0912, PLR0915
        self.set_entrydata_definition()
        data_file = mainfile.split('/')[-1]
        data_file_with_path = mainfile.split('raw/')[-1]
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
                entry.mapper_key = jsonfile['json_mapper_class_key']
                archive.results.eln.names = [entry.mapper_key]
            except KeyError:
                logger.error(
                    'Missing keys for jsonmapper file (json_mapper_class_key).'
                )
            logger.info('Starting search for already existing mappers with same key.')
            if not isinstance(archive.m_context, ClientContext):
                search_result = search(
                    owner='all',
                    query={
                        'results.eln.sections:any': ['JsonMapper'],
                        'results.eln.names:any': [entry.mapper_key],
                    },
                    user_id=archive.metadata.main_author.user_id,
                )
                if len(search_result.data) > 0:
                    logger.error(
                        'At least one mapper with the same key has been found.'
                    )

            subsections = []
            for key in jsonfile.keys():
                if key == 'json_mapper_class_key':
                    continue
                subsection = jsonfile[key]
                if 'is_main' in subsection and subsection['is_main'] == 'True':
                    sectionclass = MainMapper()
                    if (
                        'main_key' in subsection
                        or 'is_archive' in subsection
                        or 'repeats' in subsection
                    ):
                        logger.error(
                            'Main section of json mapper should not contain \
                                main_key or is_archive or repeats.'
                        )
                else:
                    sectionclass = SubSectionMapper()
                    try:
                        sectionclass.main_key = subsection['main_key']
                    except KeyError:
                        logger.error(f'main_key is missing from Subsection {key}.')
                    if 'is_archive' in subsection:
                        sectionclass.is_archive = subsection['is_archive']
                    if 'repeats' in subsection:
                        sectionclass.repeats = subsection['repeats']
                sectionclass.name = key
                try:
                    sectionclass.path_to_schema = subsection['schema']
                except KeyError:
                    logger.error(f'schema is missing from Subsection {key}.')
                if 'rules' in subsection:
                    rules = []
                    for rulekey in subsection['rules'].keys():
                        rule = subsection['rules'][rulekey]
                        rulesection = MapperRule()
                        try:
                            if not (
                                'source' in rule.keys() and 'target' in rule.keys()
                            ):
                                logger.error(
                                    f'Rule {rulekey} in SubSection {key} is \
                                        missing source or target key.'
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
                                    conditionssection.regex_path = condition[condname][
                                        'regex_path'
                                    ]
                                    conditionssection.regex_pattern = condition[
                                        condname
                                    ]['regex_pattern']
                                    condlist.append(conditionssection)
                                rulesection.conditions = condlist
                        except AttributeError:
                            rulesection.name = f'{rulekey}_to_{rule}'
                            rulesection.source = rulekey
                            rulesection.target = rule
                        rules.append(rulesection)
                    sectionclass.rules = rules
                else:
                    logger.warning(
                        f'Rules section is missing from Subsection {key}. \
                            No mapping will be done.'
                    )
                sectionclass.normalize(archive, logger)
                if 'is_main' in subsection:
                    if entry.main_mapping is None:
                        entry.main_mapping = sectionclass
                    else:
                        logger.error('is_main can only be in one Subsection.')
                else:
                    subsections.append(sectionclass)
                logger.info(sectionclass.m_to_dict())
            entry.subsection_mappings = subsections
            if entry.main_mapping is None:
                logger.error('No main mapping found.')

        archive.data = entry
        archive.metadata.entry_name = data_file + ' mapper file'


def transform_subclass(subclass_mapping, logger, jsonfile):
    subclass = get_class(subclass_mapping['path_to_schema'], logger)()
    subrules = {
        'sub_transformation': Rules(
            **json.loads(createrulesjson(subclass_mapping['rules']))
        )
    }
    subtransformer = Transformer(subrules)
    transformed_sub = subtransformer.transform(jsonfile, 'sub_transformation')

    logger.info(subclass_mapping['rules'])
    logger.info(transformed_sub)

    tempunits = transformed_sub.pop('tempunits', None)
    subclass.m_update_from_dict(transformed_sub)
    if tempunits:
        for unitkey in tempunits.keys():
            from pint import UnitRegistry

            ureg = UnitRegistry(autoconvert_offset_to_baseunit=True)
            setattr(
                subclass,
                unitkey,
                subclass[unitkey].magnitude * ureg(tempunits[unitkey]),
            )
    return subclass


def map_with_nesting(mapper, mapkey, logger, archive, jsonfile):
    mapkey_parent = mapkey + '.'
    if mapkey == '':
        subclass = transform_subclass(mapper['main_mapping'], logger, jsonfile)
    else:
        for i in range(len(mapper['subsection_mappings'])):
            submap = mapper['subsection_mappings'][i]
            if submap['main_key'] == mapkey:
                subclass = transform_subclass(submap, logger, jsonfile)
    for i in range(len(mapper['subsection_mappings'])):
        submap = mapper['subsection_mappings'][i]
        shortened_mainkey = submap['main_key'].removeprefix(mapkey_parent)
        if mapkey == '':
            mapkey_parent = ''
        if (
            submap['main_key'].startswith(mapkey_parent)
            and '.' not in shortened_mainkey
        ):
            subsubclass = map_with_nesting(
                mapper, submap['main_key'], logger, archive, jsonfile
            )
            if 'is_archive' in submap.keys() and submap['is_archive']:
                sub_ref = create_archive(
                    subsubclass,
                    archive,
                    subsubclass.name + '.archive.json',
                )
                setattr(subclass, shortened_mainkey, sub_ref)
            elif 'repeats' in submap.keys() and submap['repeats']:
                subclass[shortened_mainkey].append(subsubclass)
            else:
                setattr(subclass, shortened_mainkey, subsubclass)
    return subclass


class MappedJsonParser(MatchingParser):
    def set_entrydata_definition(self):
        self.entrydata_definition = MappedJson

    def parse(self, mainfile: str, archive: EntryArchive, logger) -> None:
        self.set_entrydata_definition()
        data_file = mainfile.split('/')[-1]
        data_file_with_path = mainfile.split('raw/')[-1]
        entry = self.entrydata_definition()
        entry.json_file = data_file_with_path

        if entry.json_file:
            with archive.m_context.raw_file(entry.json_file, 'r') as file:
                jsonfile = json.load(file)

            try:
                entry.mapper_key = jsonfile['mapped_json_class_key']
            except KeyError:
                logger.error(
                    'Missing keys for mappedjson file (mapped_json_class_key).'
                )

        logger.info('Starting search for mapper with same key.')
        if not isinstance(archive.m_context, ClientContext):
            search_result = search(
                owner='all',
                query={
                    'results.eln.sections:any': ['JsonMapper'],
                    'results.eln.names:any': [entry.mapper_key],
                },
                user_id=archive.metadata.main_author.user_id,
            )
            if len(search_result.data) > 1:
                logger.error('Two or more mappers were found.')
            elif len(search_result.data) == 1:
                upload_id = search_result.data[0]['upload_id']
                entry_id = search_result.data[0]['entry_id']
                entry.mapper_reference = (
                    f'../uploads/{upload_id}/archive/{entry_id}#data'
                )

                mapper = search_result.data[0]['data']
            else:
                logger.error('No mapper was found.')

            mainclass = map_with_nesting(mapper, '', logger, archive, jsonfile)

            create_archive(
                mainclass,
                archive,
                mainclass.name + '.archive.json',
            )

        archive.data = entry
        archive.metadata.entry_name = data_file + ' json file'

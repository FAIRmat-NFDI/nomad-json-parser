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
from nomad.datamodel.results import ELN, Results
from nomad.search import (
    search,
)

from nomad_json_parser.schema_packages.jsonimport import (
    JsonMapper,
    MainMapper,
    MapperRule,
    MatchKey,
    RepeatKey,
    RepeatPath,
    RuleCondition,
    SubSectionMapper,
)


def create_rules(subsection, key, logger):  # noqa: PLR0912
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

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
import json
import logging

import pytest
from nomad.client import normalize_all, parse

# Test JsonMapper functionality

test_files = [
    'tests/data/basesection_example_mapper.json',
]
log_levels = ['error', 'critical']


@pytest.mark.parametrize(
    'parsed_mapper_archive, caplog',
    [(file, log_level) for file in test_files for log_level in log_levels],
    indirect=True,
)
def test_normalize_mapper(parsed_mapper_archive, caplog):
    """
    Tests the normalization of the parsed archive.

    Args:
        parsed_archive (pytest.fixture): Fixture to handle the parsing of archive.
        caplog (pytest.fixture): Fixture to capture errors from the logger.
    """
    normalize_all(parsed_mapper_archive)

    assert parsed_mapper_archive.data.mapper_key == 'basesectionexamplemapper'
    assert len(parsed_mapper_archive.data.subsection_mappings) == 4  # Noqa: PLR2004
    assert parsed_mapper_archive.data.main_mapping.name == 'main_schema'


def test_mapping_function():
    from nomad_json_parser.parsers.parser import map_with_nesting

    mapper_archive = parse('tests/data/basesection_example_mapper.json')[0]

    normalize_all(mapper_archive)

    with open('tests/data/basesection_example_data.json') as file:
        jsonfile = json.load(file)

    archive = parse('tests/data/basesection_example_data.json')[0]

    logger = logging.getLogger(__name__)

    archive_list = []

    result = map_with_nesting(
        mapper_archive['data'].m_to_dict(),
        mapper_archive['data']['main_mapping']['name'],
        logger,
        archive,
        jsonfile,
        archive_list,
    )

    assert len(result) == 10  # Noqa: PLR2004
    assert result.steps[1].name == 'Stirring'
    assert result.steps[1].duration.magnitude == 300  # Noqa: PLR2004
    assert result.steps[1].duration.units == 'second'


def test_normalize_mapped():
    """
    Tests the normalization of the parsed archive.

    Args:
        parsed_archive (pytest.fixture): Fixture to handle the parsing of archive.
        caplog (pytest.fixture): Fixture to capture errors from the logger.
    """
    test_files = 'tests/data/basesection_example_data.json'

    entry_archive = parse(test_files)[0]

    assert entry_archive.data.mapper_key == 'basesectionexamplemapper'

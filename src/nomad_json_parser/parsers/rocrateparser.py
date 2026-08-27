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
from pyld import jsonld

if TYPE_CHECKING:
    from nomad.datamodel.datamodel import (
        EntryArchive,
    )

import json
import re

from nomad.datamodel import EntryArchive

from nomad_json_parser.parsers.mappedjsonparser import MappedJsonParser


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
                            './'
                            + data_file_with_path.removesuffix(
                                'ro-crate-metadata.json'
                            ),  # noqa: E501
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

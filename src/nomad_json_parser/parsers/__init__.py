from nomad.config.models.plugins import (
    ParserEntryPoint, 
)


from pydantic import Field


class JsonMapperParserEntryPoint(ParserEntryPoint):
    def load(self):
        from nomad_json_parser.parsers.parser import JsonMapperParser

        return JsonMapperParser(**self.dict())


json_mapper_parser = JsonMapperParserEntryPoint(
    name='MapperParser for Json Mapper files',
    description="""Parser for Json Mapping files.""",
    mainfile_name_re=r'.+\.json',
    # mainfile_mime_re='application/json',
    mainfile_contents_dict={'__has_key': r'\$json_mapper_class_key'},
)


class MappedJsonParserEntryPoint(ParserEntryPoint):
    def load(self):
        from nomad_json_parser.parsers.parser import MappedJsonParser

        return MappedJsonParser(**self.dict())


mapped_json_parser = MappedJsonParserEntryPoint(
    name='JsonParser for Json Mapped files',
    description="""Parser for Json Mapped files.""",
    mainfile_name_re=r'.+\.json',
    # mainfile_mime_re='application/json',
    mainfile_contents_dict={'__has_key': r'\$mapped_json_class_key'},
)


class ROCrateParserEntryPoint(ParserEntryPoint):


    json_matching_key: str = Field(
        'default_key',
        description="""
        The json mapper key to map the uploaded ROCrate object.
        """,
    )    


    json_matching_re: str = Field(
        r'.*',
        description="""
        The regex to match to full file content.
        """,
    )    


    def load(self):
        from nomad_json_parser.parsers.parser import ROCrateParser

        return ROCrateParser(**self.dict())


ro_crate_parser = ROCrateParserEntryPoint(
    name='JsonParser for ROCrate files.',
    description="""Parser for ROCrate files.""",
    level=2,
    mainfile_name_re=r'.*ro-crate-metadata.json$',
)
from nomad.config.models.plugins import (
    ParserEntryPoint,
)


class JsonMapperParserEntryPoint(ParserEntryPoint):
    def load(self):
        from nomad_json_parser.parsers.parser import JsonMapperParser

        return JsonMapperParser(**self.dict())


json_mapper_parser = JsonMapperParserEntryPoint(
    name='MapperParser for Json Mapper files',
    description="""Parser for Json Mapping files.""",
    mainfile_name_re=r'.+\.json',
    mainfile_mime_re='application/json',
    mainfile_contents_dict={'__has_key': '$json_mapper_class_key'},
)


class MappedJsonParserEntryPoint(ParserEntryPoint):
    def load(self):
        from nomad_json_parser.parsers.parser import MappedJsonParser

        return MappedJsonParser(**self.dict())


mapped_json_parser = MappedJsonParserEntryPoint(
    name='JsonParser for Json Mapped files',
    description="""Parser for Json Mapped files.""",
    mainfile_name_re=r'.+\.json',
    mainfile_mime_re='application/json',
    mainfile_contents_dict={'__has_key': '$mapped_json_class_key'},
)

from nomad.config.models.plugins import (
    SchemaPackageEntryPoint,
)


class JsonMapperEntryPoint(SchemaPackageEntryPoint):
    def load(self):
        from nomad_json_parser.schema_packages.jsonimport import m_package

        return m_package


json_mapper_schema_package = JsonMapperEntryPoint(
    name='JSON Mapper Importer',
    description='Schema package to import JSON data files via a defined mapping.',
)


class ExampleSchemaEntryPoint(SchemaPackageEntryPoint):
    def load(self):
        from nomad_json_parser.schema_packages.example import m_package

        return m_package


example_schema_package = ExampleSchemaEntryPoint(
    name='JSON Mapper Example',
    description='This example upload contains a mapper file and the respective JSON \
    file to be parsed into the schema in example.py',
)

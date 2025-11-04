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

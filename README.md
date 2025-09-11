# NOMAD's JSON Mapper plugin
This is a plugin for [NOMAD](https://nomad-lab.eu) which allows to create mappings from JSON into NOMAD schemas and parse the suitable JSON data files accordingly.

The plugin allows to create specific JSON files which specify the mapping of data into NOMAD schemas. These mapper files are
identified by the presence of the key `json_mapper_class_key`.

JSON data files are identified by the presence of the key `mapped_json_class_key`. If a mapper with the same key value exists, the data will be parsed into NOMAD entries according to the mapping.

## Getting started
`nomad-measurements` can be installed to your oasis via the steps given in [here](https://github.com/FAIRmat-NFDI/nomad-distro-template?tab=readme-ov-file#adding-a-plugin).

### Setting up your OASIS
Read the [NOMAD oasis documentation](https://nomad-lab.eu/prod/v1/docs/howto/oasis/configure.html#plugins) for details on how to add the plugin on your NOMAD instance.

You don't need to modify the ```nomad.yaml``` configuration file of your NOMAD instance, beacuse the package is pip installed and all the available modules (entry points) are loaded.
To include, instead, only some of the entry points, you need to specify them in the ```include``` section of the ```nomad.yaml```. In the following lines, a list of all the available entry points:

```yaml
plugins:
  include:
    - "nomad_json_parser.schema_packages:json_mapper_schema_package"
    - "nomad_json_parser.parsers:json_mapper_parser"
    - "nomad_json_parser.parsers:mapped_json_parser"
    - "nomad_json_parser.schema_packages:example_schema_package"
    - "nomad_json_parser.example_uploads:example_upload_entry_point"
 ```


### Further documentation

For a detailed documentation on how this plugin works and how to create JSON mapper, please refer to the [documentation](https://fairmat-nfdi.github.io/nomad-json-parser/).
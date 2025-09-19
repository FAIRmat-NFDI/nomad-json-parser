# Introduction

This is an example of a mapping from a JSON file to a NOMAD schema. Firstly, a mapping needs to be defined in JSON and parsed into a JsonMapper entry. Secondly, all uploaded JSON data files will be parsed into MappedJson entries and when the key between mapper and data is the same, the contents of the data file are transformed into the respective NOMAD schema.

# Viewing uploaded data

Below, you find an overview of your uploaded data.
Click on the `> /` button to get a list of your data or select **FILES** from the top menu of this upload.

The `example_mapper.json` contains the `json_mapper_class_key` against which the data files are tested later on. Additionally, it defines the classes used in the NOMAD schema and contains the rules how to map between the data JSON and the schema. The mapping rules follow the ones of the [NOMAD Transformer](https://nomad-lab.eu/prod/v1/docs/howto/programmatic/json_transformer.html).

The `example_data.json` contains the `mapped_json_class_key` to identify the suitable mapper and all data that should be mapped into the NOMAD schema.

You can create your own mapper and data files and try them out here or in separate uploads.

# Where to go from here?

If you're interested in using this plugin and NOMAD in general you'll find support at the [documentation](https://fairmat-nfdi.github.io/nomad-json-parser/) and [FAIRmat](https://www.fairmat-nfdi.eu/fairmat).

If you have any questions about this example you may contact [Jonathan Noky](https://www.fairmat-nfdi.eu/fairmat/about-fairmat/team-fairmat) from the FAIRmat consortium.
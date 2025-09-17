# Explanation

In this section, the parsing process is described more in detail. All possible keys can be found [here](reference/references.md), an example with many features included can be found in the example uploads.

## The mapper file

A mapper file is recognized by the parser, if it is a ".json" file and contains the text ```json_mapper_class_key```. If there is a key ```json_mapper_version``` present, the respective version number is read, otherwise it is set to 1.

Then the parser searches, if there already is a JSON mapper with the same key and version present. If so, the process is stopped, as there cannot be two mappers with the same key and version. If not, the JSON is read out the ```JSONMapper``` schema from this plugin is filled with the information from the file. All rules are read in the format of the [Transformer](https://nomad-lab.eu/prod/v1/docs/howto/programmatic/json_transformer.html), except simple rules, which allow for a shorter ```"source": "target"``` syntax and are internally translated into the Transformer syntax.

## The data file

A data file is recognized by the parser, if it is a ".json" file and contains the text ```mapped_json_class_key```. If there is a key ```mapped_json_version``` present, the respective version number is read, otherwise the highest version of the parser will be used.

Then the parser searches, if there is a JSON mapper with the same key and, if selected via ```mapped_json_version```, version present. If there is at least one mapper and no specific version is selected, the highest version found will be used. The parser now creates all schemas specified in the mapper, fills them with data from the data file according to the rules, and links them as specified in the mapper. In the end, the main entry (and possible additional archive entries) are created in the upload.
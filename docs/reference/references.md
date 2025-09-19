# References

This page will provide information to all possible keys in the JSON files.

## The mapper file

On the top level of the JSON, the following keys are possible:

- ```json_mapper_class_key```: Mandatory, gives the key to find matching data entries. Format: string.
- ```json_mapper_version```: Optional, defines, which version this mapper is for the respective key. Default value: 1. Format: integer.

The JSON mapper the contains information of the schemas to map. Each of these starts with a name, which has no further meaning. Possible keys for each schema are:

- ```is_main```: Optional, but has to be ```True``` for exactly one entry. Default value: False. Format: boolean.
- ```schema```: Mandatory, gives the python path to the schema to map onto. Format: string.
- ```main_key```: Mandatory for all schemas except the one with ```"is_main": "True"```. Gives the key in the main NOMAD schema, where this section is attached. Can be nested with ".". Format: string.
- ```repeats```: Optional, indicates that the ```main_key``` point is a repeatable subsection, where this schema is just appended to. Default value: False. Format: boolean.
- ```is_archive```: Optional, indicates that this schema is a separate archive and only the reference is linked in the main entry. Default value: False. Format: boolean.
- ```rules```: Mandatory, contains mapping rules for the data. Simple mappings (also nested with ".") from source to target can be given just by ```"source": "target"```, more complex mapping rules are possible as described in the [Transformer]().

## The data file

The data file has the following possible keys:

- ```json_mapper_class_key```: Mandatory, gives the key to find matching parser. Format: string.
- ```json_mapper_version```: Optional, specify, which version this mapper is used. Default value: highest. Format: integer.

Apart from these two keys, the data file can contain the data in any JSON format.

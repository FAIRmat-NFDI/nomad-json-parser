# Tutorial

The NOMAD JSON parser can parse two kinds of JSON files: Mappers and data files. The mappers define a mapping schema, which contains information about which NOMAD schemas should be created, how they are linked together, and how they are filled with data from the JSON data files. The data files contain the actual data.

## The mapper file

The mapper file is a JSON file with a fixed structure. A simple example could be as follows:
```
{
    "json_mapper_class_key": "examplemapper",
    "main_schema": {
        "is_main": "True",
        "schema": "nomad_json_parser.schema_packages.example.MainLevel",
        "rules": {
            "Mainname": "string"
            }
        },
    "Sublevel1": {
        "schema": "nomad_json_parser.schema_packages.example.SubLevel1",
        "main_key": "nesting",
        "rules": {
            "Sublevels.SublevelOne": "string"
            }
        }
    }
```

The key ```json_mapper_class_key``` has to be present, as it is used to match the mapper with the suitable data files. After that, the single NOMAD schemas and subsections are following. Here, exactly one entry has to have the key ```is_main``` set to True. Every entry other entry has to have a ```main_key``` key, which indicates, where the subsection is connected to the main entry. Every entry has to have a ```schema``` key pointing to the python path of the used schema and a ```rules``` key containing the mapping rules.

Additional possible but not neccessary keys are:
- ```is_archive```: This entry will be a separate archive and only referenced in the main entry.
- ```repeats```: This indicates a repeating subsection.

For more information see the [explanation section](../explanation/explanation.md).

## The data file

The data file is a JSON file, which contains all the important data. It could look as follows:
```
{
    "mapped_json_class_key": "examplemapper",
    "Mainname": "This is the main name",
    "Sublevels": {"SublevelOne": "This is sublevel 1 name"}
}
```

The key ```mapped_json_class_key``` has to be present, as it is used to match the data with the suitable mapper. After that, the data can follow in any JSON format.

For more information see the [explanation section](../explanation/explanation.md).
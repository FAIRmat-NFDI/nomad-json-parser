# Tutorial

The NOMAD JSON parser can parse two kinds of JSON files: Mappers and data files. The mappers define a mapping schema, which contains information about which NOMAD schemas should be created, how they are linked together, and how they are filled with data from the JSON data files. The data files contain the actual data.

## The mapper file

The mapper file is a JSON file with a fixed structure. A simple example could be as follows:
```
{
    "$json_mapper_class_key": "basesectionexamplemapper",
    "main_schema": {
        "is_main": "True",
        "schema": "nomad.datamodel.metainfo.basesections.v1.Process",
        "rules": {
            "title": "name",
            "What_did_I_do": "method",
            "location": {
                "source": "location",
                "target": "location",
                "default_value": "MPI CPfS Dresden"
            }
        }
    },
    "steps_mapping": {
        "schema": "nomad.datamodel.metainfo.basesections.v1.ProcessStep",
        "main_key": "steps",
        "repeats": "True",
        "repeat_paths": ["*"],
        "repeat_keys": ["How_long_did_it_take", {"step_description": "Stir clockwise"}],
        "rules": {
            "step_name": "name",
            "step_description": "comment",
            "How_long_did_it_take": "duration",
            "time_unit": "tempunits.duration"
        }
    },
    "sample_mapping": {
        "schema": "nomad.datamodel.metainfo.basesections.v1.CompositeSystemReference",
        "main_key": "samples",
        "repeats": "True",
        "rules": {
            "Chem.name": "name"
        },
        "subsections": {
            "sample_reference_mapping": {
                "schema": "nomad.datamodel.metainfo.basesections.v1.CompositeSystem",
                "main_key": "reference",
                "is_archive": "True",
                "rules": {
                    "Chem.labid": "lab_id",
                    "Chem.substance_formula": "name"
                }
            }
        }
    }
}
```

The key ```$json_mapper_class_key``` has to be present, as it is used to match the mapper with the suitable data files. After that, the single NOMAD schemas and subsections are following. Here, exactly one entry has to have the key ```is_main``` set to True. Every entry other entry has to have a ```main_key``` key, which indicates, where the subsection is connected to the main entry. Every entry has to have a ```schema``` key pointing to the python path of the used schema and a ```rules``` key containing the mapping rules.

Additional possible but not neccessary keys are:
- ```is_archive```: This entry will be a separate archive and only referenced in the main entry.
- ```repeats```: This indicates a repeating subsection.
- ```repeat_paths```: An array of key pathes in the data file, where the respective repeatable subsection should be matched. Uses jmespath notation and a ```*``` can be used as a wildcard.
- ```repeat_keys```: A dictionary containing keys, that need to be present to select a subsection, and key-value pairs, that need to be present to select the subsection.

For more information see the [explanation section](../explanation/explanation.md).

## The data file

The data file is a JSON file, which contains all the important data. It could look as follows:
```
{
    "$mapped_json_class_key": "basesectionexamplemapper",
    "title": "Create NaCl solution",
    "What_did_I_do": "Solution by stirring",
    "Steplist":[    {
                "step_name": "NaCl into H2O",
                "step_description": "Put NaCl into H2O",
                "time_unit": "seconds"
        },
        {
                "step_name": "Stirring 1",
                "step_description": "Stir clockwise",
                "How_long_did_it_take": 300.0,
                "time_unit": "seconds"
        },
        {
                "step_name": "Stirring 2",
                "step_description": "Stir anti-clockwise",
                "How_long_did_it_take": 5.0,
                "time_unit": "minutes"
        },
        {
                "step_name": "Stirring 3",
                "step_description": "Stir clockwise",
                "How_long_did_it_take": 600.0,
                "time_unit": "seconds"
        }
    ],
    "Chem": {
        "name": "Rocksalt",
        "labid": "JN123_NaCl",
        "substance_formula": "NaCl"
    }
} 
```

The key ```$mapped_json_class_key``` has to be present, as it is used to match the data with the suitable mapper. After that, the data can follow in any JSON format.

For more information see the [explanation section](../explanation/explanation.md).
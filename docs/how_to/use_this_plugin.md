# How to Use This Plugin

This plugin adds a simple JSON-to-NOMAD mapping layer to a NOMAD Oasis installation. It allows you to define a mapper that describes how JSON data should be transformed into Nomad entries and sub-sections.

The complete workflow is:

1. Install the plugin into your NOMAD environment.
2. Create a mapper JSON file with a unique `$json_mapper_class_key`.
3. Create one or more data JSON files with a matching `$mapped_json_class_key`.
4. Upload the data file to NOMAD and let the parser create the corresponding entries.

## Add this plugin to your NOMAD installation

Read the [NOMAD plugin documentation](https://nomad-lab.eu/prod/v1/staging/docs/plugins/plugins.html#add-a-plugin-to-your-nomad) for all details on how to deploy the plugin to a NOMAD instance.

For this plugin, the relevant entry points are loaded automatically when the package is installed. In a custom configuration, you can also restrict them explicitly in `nomad.yaml`:

```yaml
plugins:
  include:
    - "nomad_json_parser.schema_packages:json_mapper_schema_package"
    - "nomad_json_parser.parsers:json_mapper_parser"
    - "nomad_json_parser.parsers:mapped_json_parser"
    - "nomad_json_parser.example_uploads:example_upload_entry_point"
```

## Create a mapper file

A mapper file is a JSON document that describes the NOMAD schema and the rules for mapping source keys to NOMAD fields. The mapper is identified by the presence of `$json_mapper_class_key`.

The following example is based on the project test data and maps a process into a NOMAD `Process` entry with repeated `steps` and nested sample information:

```json
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
    "repeat_paths": ["*.Steps"],
    "repeat_keys": ["How_long_did_it_take", {"time_unit": "seconds"}],
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
    "repeat_paths": ["Chem.*"],
    "rules": {
      "name": "name"
    },
    "subsections": {
      "sample_reference_mapping": {
        "schema": "nomad.datamodel.metainfo.basesections.v1.CompositeSystem",
        "main_key": "reference",
        "is_archive": "True",
        "rules": {
          "labid": "lab_id",
          "substance_formula": "name"
        }
      }
    }
  }
}
```

### Required mapper fields

Each mapper contains one main schema and any number of additional mappings.

- `$json_mapper_class_key`: unique identifier used to match the mapper to incoming data.
- `main_schema`: the root NOMAD section to be created. Exactly one mapping must set `is_main` to `True`.
- `schema`: Python path to the NOMAD schema class.
- `rules`: mapping rules that define how source JSON keys map to target NOMAD fields.
- `main_key`: where the subsection is attached in the parent object.

### Useful optional fields

- `repeats`: marks a subsection as repeatable.
- `repeat_paths`: list of JSON paths where repeated items can be found. JMESPath-like syntax is used and `*` can act as a wildcard.
- `repeat_keys`: conditions that must be present in a record before it is treated as a repeatable item.
- `is_archive`: creates a separate archive entry and stores a reference to it in the parent object.
- `subsections`: nested mappings attached to a given section.

## Create a data file

The data file contains the actual information to be ingested. It must include `$mapped_json_class_key` and its value must match the mapper key.

```json
{
  "$mapped_json_class_key": "basesectionexamplemapper",
  "title": "Create NaCl solution",
  "What_did_I_do": "Solution by stirring",
  "Steplist": [
    {
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
    }
  ],
  "Chem": {
    "name": "Rocksalt",
    "labid": "JN123_NaCl",
    "substance_formula": "NaCl"
  }
}
```

In this particular example:

- `title` maps to the NOMAD entry name.
- `What_did_I_do` maps to the process method.
- `Steplist` becomes repeated `ProcessStep` objects.
- `How_long_did_it_take` and `time_unit` are combined into a duration field.
- `Chem` is mapped into a nested sample/reference object.

## Rules and value transformation

The mapper uses a rule syntax inspired by NOMAD's JSON transformer. Simple rules can be written in the compact form:

```json
"source_key": "target_field"
```

This means that the value from the source file is copied to the target field in the NOMAD schema.

The more explicit form is also supported:

```json
"location": {
  "source": "location",
  "target": "location",
  "default_value": "MPI CPfS Dresden"
}
```

This allows you to:

- select a different source field than the target field,
- set a default value,
- convert values during the mapping step,
- work with units and typed quantities.

## Repeated sections

Repeated sections are important in many data sets. The example uses an array of process steps:

```json
"repeat_paths": ["*.Steps"],
"repeat_keys": ["How_long_did_it_take", {"time_unit": "seconds"}]
```

This tells the parser to iterate over the listed paths and create one repeated object per valid item. The matching conditions limit which entries are accepted.

## Troubleshooting

Common issues when creating a mapper are:

- Key mismatch: the mapper key and data key must match exactly.
- Missing `is_main`: the parser expects exactly one root section to be marked as the main entry.
- Missing `main_key`: every subsection must state where it belongs in the parent schema.
- Wrong `repeat_paths`: repeated entries are only created if the path points to the actual list in the data file.
- Typo in field names: the JSON field names are case-sensitive and must match the source file.

## Next steps

After defining a valid mapper and matching data file, you can upload the data to a NOMAD Oasis and inspect the produced entries. The project includes example mapper and data files in the test suite and example uploads, which are useful references when building new mappings.

For a more complete overview of the plugin internals, see the [tutorial](../tutorial/tutorial.md) and [explanation](../explanation/explanation.md) sections.


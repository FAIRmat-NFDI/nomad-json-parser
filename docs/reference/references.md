# Mapping reference

This page documents the mapper keys and rule objects used by the NOMAD JSON parser. It is intended as a practical reference for building and debugging mapper files.

## Quick cheat sheet

Use this when you just need the essentials:

- `$json_mapper_class_key` — required; identifies the mapper and must match the data file's `$mapped_json_class_key`.
- `main_schema` — required; exactly one mapping must have `is_main: true`.
- `schema` — required; NOMAD schema class path.
- `main_key` — required for non-main sections; where the subsection is attached.
- `rules` — required; maps source JSON fields to target schema fields.
- `repeats` — set to `true` for repeated subsections.
- `repeat_paths` — list of repeated JSON paths to inspect.
- `repeat_keys` — optional filters for selecting valid repeated items.
- `is_archive` — creates a separate archive item and stores a reference.
- compact rule: `"source_key": "target_field"`
- explicit rule: `"source_key": { "source": "source_key", "target": "target_field", "default_value": "..." }`

### Minimal mapper pattern

```json
{
  "$json_mapper_class_key": "my_mapper",
  "main_schema": {
    "is_main": true,
    "schema": "nomad.datamodel.metainfo.basesections.v1.Process",
    "rules": {
      "title": "name",
      "description": "method"
    }
  },
  "steps_mapping": {
    "schema": "nomad.datamodel.metainfo.basesections.v1.ProcessStep",
    "main_key": "steps",
    "repeats": true,
    "repeat_paths": ["Steplist[*]"],
    "rules": {
      "step_name": "name",
      "step_description": "comment"
    }
  }
}
```

---

## 1. Top-level mapper structure

A mapper is a JSON object recognized by the parser when it contains a `$json_mapper_class_key` entry. The mapper describes which NOMAD schema to create, how it is connected to the main entry, and which data fields are mapped into the target fields.

```json
{
  "$json_mapper_class_key": "my_mapper",
  "$json_mapper_version": 1,
  "main_schema": {
    "is_main": true,
    "schema": "nomad.datamodel.metainfo.basesections.v1.Process",
    "rules": {
      "title": "name",
      "description": "method"
    }
  },
  "steps_mapping": {
    "schema": "nomad.datamodel.metainfo.basesections.v1.ProcessStep",
    "main_key": "steps",
    "repeats": true,
    "repeat_paths": ["Steplist[*]"],
    "rules": {
      "step_name": "name",
      "step_description": "comment"
    }
  }
}
```

### Top-level keys

- `$json_mapper_class_key` — required string. This key identifies the mapper and must match the data file's `$mapped_json_class_key`.
- `$json_mapper_version` — optional integer. If omitted, the default version is 1. If multiple versions exist, the selected version is used by the parser.
- `main_schema` — required object. The root section being created. Exactly one mapping must use `is_main: true`.
- named mapping entries such as `steps_mapping`, `sample_mapping`, `analysis_mapping` — optional objects. Each defines a NOMAD subsection, repeated section, archive section, or nested mapping.

---

## 2. Section mapping keys

Each mapping entry has its own schema configuration. The most common keys are listed below.

### Required and common keys

- `schema` — required string. Fully qualified Python path to the NOMAD schema class.
- `rules` — required object. Mapping rules describing how JSON keys are transformed into schema fields.
- `is_main` — optional bool. Set to `true` for exactly one root mapping. Only the main entry is created as the top-level object.
- `main_key` — required for all non-main mappings. Specifies where the mapped object is attached. Examples:
  - `steps`
  - `samples`
  - `chemistry`
  - `process.steps`

### Repetition and nesting

- `repeats` — optional bool. Marks a subsection as repeatable and appends multiple instances to the same `main_key` list.
- `repeat_paths` — optional list of strings. Describes where repeated sequences live in the data file. JMESPath-like paths are used and `*` may be used as a wildcard.
- `repeat_keys` — optional list. Used together with wildcard-based `repeat_paths` to confirm that a candidate item matches the expected structure or content.
- `is_archive` — optional bool. Creates a separate archive entry and links it to the parent section by reference instead of embedding it directly.
- `subsections` — optional object. Defines nested mappings that belong to a section.

### Examples

#### Simple nested field

```json
"sample_mapping": {
  "schema": "nomad.datamodel.metainfo.basesections.v1.CompositeSystemReference",
  "main_key": "samples",
  "repeats": true,
  "rules": {
    "name": "name"
  }
}
```

#### Nested archive subsection

```json
"sample_reference_mapping": {
  "schema": "nomad.datamodel.metainfo.basesections.v1.CompositeSystem",
  "main_key": "reference",
  "is_archive": true,
  "rules": {
    "labid": "lab_id",
    "substance_formula": "name"
  }
}
```

---

## 3. Rule syntax

A mapper rule tells the parser how to read a value from the JSON source and write it to a target field in the NOMAD schema. There are two supported styles: compact shorthand and explicit object syntax.

### 3.1 Compact rule syntax

```json
"title": "name"
```

This means:

- source key: `title`
- target field: `name`
- read from the data file and assign to the named target field in the schema.

Nested keys can use dot notation:

```json
"Chem.name": "name"
```

This is equivalent to selecting a nested value from the `Chem` object and writing it to the target field `name`.

### 3.2 Explicit rule object

```json
"location": {
  "source": "location",
  "target": "location",
  "default_value": "MPI CPfS Dresden"
}
```

The explicit form allows the following keys:

- `source` — required string. Field in the input JSON to read.
- `target` — required string. Field in the NOMAD schema to write to.
- `default_value` — optional string or scalar. Used when the source field is absent or empty.
- `use_rule` — optional string. Advanced transformation hook used by the underlying NOMAD transformer.
- `conditions` — optional array of conditions. Restricts a rule by checking source values.
- `target_type` — optional string. Can force conversion to a specific type such as `array` or `float`.

### 3.3 Condition-based rules

Rules may include conditions, which are checked before assignment:

```json
"duration": {
  "source": "How_long_did_it_take",
  "target": "duration",
  "conditions": [
    {
      "name": "duration_exists",
      "regex_path": "How_long_did_it_take",
      "regex_pattern": ".+"
    }
  ]
}
```

This tells the parser to apply the rule only if the source value is present and matches the stated condition.

---

## 4. Repeatable sections and matching logic

Repeatable sections are used when the source data contains arrays or repeated objects. The parser resolves them using `repeat_paths` and `repeat_keys`.

### `repeat_paths`

```json
"repeat_paths": ["Steplist[*]", "Chem.*"]
```

This tells the parser to look for repeated entries under these JSON paths. The wildcard `*` indicates an iteration over list items or object members.

### `repeat_keys`

```json
"repeat_keys": [
  "How_long_did_it_take",
  {"time_unit": "seconds"}
]
```

A repeat candidate is accepted only if all required keys are present and the conditions match. In practice, this is used to distinguish one repeated item from another or to select only the entries that belong to a given step type.

A repeat can also be filtered using regex-like matching patterns when the object is keyed by dynamic field names.

---

## 5. Matching keys and dynamic path resolution

The parser supports dynamic resolution of repeated paths and matching conditions using special objects in `repeat_keys` and related matching structures. These are useful when the input JSON contains nested or variable identifiers.

### Example of a matching object

```json
"repeat_keys": [
  {"step_name": "Stir.*"}
]
```

This checks whether the field `step_name` exists and matches the regex-like pattern `Stir.*`.

The parser can also evaluate dictionaries where keys are matched against dynamic values:

```json
"match_keys": [
  {"name": "^sample_.*"}
]
```

This pattern becomes important when the same mapper is reused for different data layouts or when data keys vary by experiment.

---

## 6. Common field semantics

### `main_key`

This is the target path where a nested object is attached inside the parent object.

Examples:

- `steps`
- `samples`
- `process.steps`

If a section is not marked as main, it must always provide a valid `main_key`.

### `is_archive`

When `is_archive` is true, a subsection is created as a separate archive entry and only a reference is stored in the main object. This is especially useful for large complex objects or independent nested records.

### `repeats`

When `repeats` is true, the parser appends new section instances to the list at `main_key` instead of replacing a single value.

---

## 7. Rule behavior and type coercion

The parser performs a few useful conversions automatically when the target type is known. For example, if `target_type` is set to `float`, the parser attempts to coerce the source value to a float. If `target_type` is `array`, the value is wrapped as a one-element list when needed.

This is especially useful for values like:

```json
"How_long_did_it_take": {
  "source": "How_long_did_it_take",
  "target": "duration",
  "target_type": "float"
}
```

and for repeated values that should be stored as a list.

---

## 8. Full example

```json
{
  "$json_mapper_class_key": "basesectionexamplemapper",
  "main_schema": {
    "is_main": true,
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
    "repeats": true,
    "repeat_paths": ["Steplist[*]"],
    "repeat_keys": ["How_long_did_it_take"],
    "rules": {
      "step_name": "name",
      "step_description": "comment",
      "How_long_did_it_take": {
        "source": "How_long_did_it_take",
        "target": "duration",
        "target_type": "float"
      },
      "time_unit": "tempunits.duration"
    }
  },
  "sample_mapping": {
    "schema": "nomad.datamodel.metainfo.basesections.v1.CompositeSystemReference",
    "main_key": "samples",
    "repeats": true,
    "repeat_paths": ["Chem.*"],
    "rules": {
      "name": "name"
    },
    "subsections": {
      "sample_reference_mapping": {
        "schema": "nomad.datamodel.metainfo.basesections.v1.CompositeSystem",
        "main_key": "reference",
        "is_archive": true,
        "rules": {
          "labid": "lab_id",
          "substance_formula": "name"
        }
      }
    }
  }
}
```

This example demonstrates the main concepts:

- root entry mapping,
- repeated step creation,
- nested sample attachment,
- dynamic target field assignment,
- explicit type coercion for numerical values.

---

## 9. Quick checklist

When building a mapper, verify the following:

- `$json_mapper_class_key` is present and unique.
- there is exactly one `is_main` entry.
- every non-main mapping has a `main_key`.
- `rules` uses valid source and target names.
- `repeat_paths` points to the actual repeated array or object in the source data.
- `repeat_keys` filters matches when needed.
- nested mappings use `subsections` or `main_key` consistently.

For more practical examples, see the tutorial and the example JSON files included with the plugin.

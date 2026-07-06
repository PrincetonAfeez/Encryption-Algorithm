# FeltCrypto Schema

This folder contains simple JSON Schema documents for the project's
JSON-compatible data structures.

## Files

- `lesson.schema.json` validates the dictionary returned by `Lesson.metadata()`.
- `demo-result.schema.json` validates the dictionary returned by
  `DemoResult.as_dict()`.
- `encrypted-package.schema.json` validates the JSON document produced by
  `encode_package()`.

The schemas use JSON Schema Draft 2020-12. They do not change the runtime
behavior of FeltCrypto and do not add a package dependency.

## Optional validation

Install a validator only when you need one:

```console
python -m pip install jsonschema
```

Example:

```python
import json

from jsonschema import validate

schema = json.loads(
    open("Schema/demo-result.schema.json", encoding="utf-8").read()
)
validate(instance=result.as_dict(), schema=schema)
```

Place the `Schema` folder at the repository root.

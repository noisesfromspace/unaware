## Description

`unaware` is a command-line tool for masking sensitive data within JSON, XML, and CSV files. It processes data from files or `stdin` and anonymizes specified property values. These values mimick the length and appearance of their original data types.

The program is a cross-platform, statically linked binary with no external dependencies. It leverages streaming and concurrency to efficiently process large files offline.

> 🌱 **Tired of Github?** This repository is available through Radicle. View it here: [rad:z3bTedCQLQRkCdAmKKZTMSBimNp4J](https://git.boers.email/nodes/seed.boers.email/rad:z3bTedCQLQRkCdAmKKZTMSBimNp4J)

### Installation

Build the program from source:

```shell
go build -o unaware main.go
```

Alternatively, check the releases folder for pre-built binaries.

### Usage

```
Anonymize data in JSON, XML, and CSV files by replacing values with realistic-looking alternatives.

Use the -method deterministic option to preserve relationships by ensuring identical
input values get the same masked output value. By default every run uses a
random salt, use STATIC_SALT=test123 environment variable for consistent
masking.

  -cpu int
    	Numbers of cpu cores used (default 4)
  -exclude value
    	Glob pattern to exclude keys from masking (can be specified multiple times)
  -format string
    	The format of the input data (json, xml, csv or text) (default "json")
  -in string
    	Input file path (default: stdin)
  -include value
    	Glob pattern to include keys for masking (can be specified multiple times)
  -method string
    	Method of masking (random or deterministic) (default "random")
  -out string
    	Output file path (default: stdout)
```

### Examples

#### JSON from a file

```shell
./unaware -in source.json -out anonymized.json
```

#### XML from stdin with deterministic masking

```shell
cat source.xml | ./unaware -format xml -method deterministic > masked.xml
```

### Filtering

You can control which fields are masked using the `-include` and `-exclude` flags, which both accept glob patterns (e.g., `user.*`, `session.ip_*`, `**.email`, `user.*.id`).

- **Default Behavior:** If no flags are used, all fields are masked.
- **Using `-include`:** Specifies which fields *should* be masked. When `-include` patterns are used, only fields matching them will be considered for masking.
- **Using `-exclude`:** Specifies fields that *should not* be masked, creating exceptions. When `-exclude` is used, masked values are prefixed with `mask-` so the output clearly shows which fields were altered.
- **Combining Flags:** When used together, `-exclude` always takes precedence. A field is only masked if it matches an `-include` pattern but does *not* match an `-exclude` pattern. If only `-exclude` is used, all fields are masked *except* for those that match an exclusion pattern.

### XML attribute values

Globs normally match element and attribute *names* (joined with `.`). To match on an XML attribute's *value*, append an `attrName=attrValue` segment right after the element name. For example, given:

```xml
<Message>
  <field name="Body">
    <value>secret</value>
  </field>
</Message>
```

the `<value>` content is addressable as `Message.field.name=Body.value`, so you can mask only the Body field's value while leaving others alone:

```shell
unaware -format xml -include "Message.field.name=Body.value" < source.xml
# or at any depth:
unaware -format xml -include "**.name=Body.value" < source.xml
```

This works for any attribute, not just `name` (e.g. `id=123`).

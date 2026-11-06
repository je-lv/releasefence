# Policy file

`scan`, `manifest` and `verify` accept `--policy FILE`. The file is a JSON object with only these keys:

```json
{
  "max_file_bytes": 10485760,
  "max_total_bytes": 104857600,
  "large_file_bytes": 5242880,
  "forbidden_globs": ["*.bak", "private/*"],
  "ignore": [{"rule_id": "RF400", "path_glob": "examples/*.bak"}]
}
```

Omitted keys use the defaults above (empty arrays for globs and ignores).
Size values must be positive integers, excluding booleans. Unknown keys,
duplicate JSON keys, nonstandard JSON constants, malformed entries and empty
globs are rejected. Ignore entries require exactly `rule_id` and `path_glob`.
Globs use case-sensitive Python `fnmatchcase` against POSIX relative paths;
`*` can match `/`. Backslashes are rejected in globs. Rule IDs are exact
strings; unknown IDs are rejected. Suppressing an error makes it
nonblocking, so review suppressions before accepting a release.

Suppressed findings still appear in `--format json` under `suppressions`, each with the
policy entry that matched, so an audit can see exactly what was ignored. The text report
counts them in its last line.

A real example: this repository's own [releasefence.json](../releasefence.json) suppresses
the deliberate findings in `fixtures/unsafe`, one rule and one path at a time.

Rule IDs and what they mean: [RULES.md](RULES.md).

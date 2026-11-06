# Changelog

## 0.1.0

First public release.

- `scan` a directory or ZIP: inventory with sizes and SHA-256 hashes, and 27 rules for secrets,
  unsafe paths, archive tricks and publication mistakes.
- `manifest` and `verify`: record a clean release and report later additions, removals and changes.
- JSON policy file: size limits, forbidden globs and audited suppressions.
- Text output grouped by file with the verdict last; deterministic JSON output.
- No runtime dependencies; Python 3.11 or later.

# ReleaseFence design

The runtime is a Python 3.11+ standard-library package. `inventory.py` owns
filesystem/archive streaming, `detectors.py` owns name and content rules,
`model.py` defines records and size limits, `core.py` applies policy and orders
the report, `render.py` formats the text report, and `cli.py` publishes
manifests and compares inventories.

The scanner hashes bytes as it reads bounded chunks and never extracts ZIP
members. Findings describe the rule and path, without matching secret
material. The report contains only normalized relative file paths, byte
sizes, SHA-256 hashes, findings and explicit suppression records. Sorting
and omission of timestamps/absolute roots make reports deterministic for a
stable input and policy. Control, bidi and undecodable characters in paths
are escaped before they reach the terminal.

The per-file limit prevents large-member reading and the total limit bounds
aggregate uncompressed bytes. Input metadata is untrusted. Directory files
must remain ordinary, nonsymlink files when opened, and their stable metadata
and actual streamed byte count must agree before they are trusted. ZIP member
names and Unix file types are checked before reading. Reports are evidence
of a particular scan, not a durable filesystem snapshot.

Policies are validated before scanning. Case-sensitive POSIX path globs add
forbidden files or suppress exact rule IDs. Suppressed findings retain their
original blocking flag plus the matching suppression configuration; the
report's `blocking` flag reflects active findings only. Operators must audit
suppression records, especially when producing manifests.

Manifest publication uses a flushed temporary file in the output directory
and an atomic hard-link creation so an existing target cannot be overwritten,
even by a concurrent writer. Temporary files are removed after publication.
Hard-link support is required; unsupported filesystems fail with exit 2.
The scanner never writes to the inspected source. Manifest output inside the
source directory is refused to avoid self-inventory ambiguity.

Verification validates manifest schema, unique safe paths, nonnegative sizes
and lowercase SHA-256 before comparing exact file records. Inventory changes
are blocking independently of security-policy suppression. A manifest is an
unsigned integrity reference; its authenticity depends on trusted storage.

## Rule families

- RF1xx: filesystem/ZIP structure, unsafe names, read stability and limits.
- RF2xx: private-key and bearer/API-token content patterns.
- RF3xx: publication filename mistakes, Git internals, junk and large files.
- RF400: a file matches a policy forbidden glob.

The scanner implementation defines individual rule IDs and explanations;
automated adversarial tests exercise their behavior. Tests use generated ZIPs
and synthetic credentials, never real secrets or external targets.

## Stable scanner rule catalogue

| ID | Severity | Meaning |
|---|---|---|
| RF101 | error | symbolic link |
| RF102 | error | special file type (device, socket, FIFO or unknown) |
| RF103 | error | path escapes the input root |
| RF104 | error | absolute archive member path |
| RF105 | error | '..' traversal in archive member path |
| RF106 | error | backslash in path |
| RF107 | error | duplicate or colliding archive path after normalization (same name twice, file vs directory, file used as a parent directory) |
| RF108 | error | encrypted archive member |
| RF109 | error | file changed while being read |
| RF110 | error | file exceeds per-file size limit |
| RF111 | error | input exceeds total size limit |
| RF112 | error | unreadable or corrupt entry |
| RF113 | error | control, bidi or undecodable characters in path |
| RF114 | error | directory nesting too deep |
| RF115 | warning | hard-linked file |
| RF116 | error | archive member name normalizes to the archive root (`.`, `./`, `/`, empty) |
| RF201 | error | private key PEM block |
| RF202 | error | Glassboard bearer token |
| RF203 | error | GitHub token |
| RF204 | error | OpenAI API key |
| RF301 | error | environment (.env) file |
| RF302 | error | credential-like file name |
| RF303 | error | version-control internals |
| RF304 | warning | editor, OS or build junk |
| RF305 | warning | unexpectedly large file |
| RF307 | warning | possible credential file |
| RF400 | error | policy forbidden glob |

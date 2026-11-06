# ReleaseFence threat model

ReleaseFence inspects a directory or ZIP before publication and reports
integrity and likely secret exposure. It is an offline reviewer, not a
sandbox and not a signer. The rule catalogue and severities live in
`releasefence/model.py` and are summarized in `DESIGN.md`.

## Assets

- Source bytes that are about to be published.
- Secrets that must not ship: private keys, bearer tokens, API keys, and
  credential files.
- The scan report and manifest, which reviewers and later `verify` runs trust
  as evidence about one input.

## Trust boundary

The operator chooses the path and the optional policy. Everything under that
path is untrusted input: names, sizes, ZIP metadata, symlink targets, and
file bytes. ReleaseFence does not execute, import, render, or extract that
input. Directory walks use `lstat`, `O_NOFOLLOW`, and directory file
descriptors. ZIP members are streamed with `zipfile` and never written out.

Reports name the rule and the path. Matched secret text is not stored in
findings and is not printed. Control, bidi, and undecodable name bytes are
escaped in every output and reported as `RF113`.

A clean exit status means this scan produced no blocking findings. It does
not mean the tree is free of every possible secret, and it does not
authenticate the publisher.

## Threats and what the scan does

| Threat | Result |
|---|---|
| ZIP path that is absolute, contains `..`, or uses `\` | `RF104`, `RF105`, `RF106`. Blocking. The member is still described so the report shows the dangerous name; manifest publication stays blocked. |
| Duplicate or colliding ZIP member paths | `RF107`. Paths are compared after normalization (separators, `.` segments) in one namespace for files and directories, so `same` with `same/`, `a/./b` with `a/b`, and a file `a` alongside `a/b` all collide. Extractors disagree about which entry wins. |
| ZIP member whose name normalizes to the archive root (`.`, `./`, `/`, empty) | `RF116`. The member names no file and is not inventoried or read. |
| Encrypted ZIP member | `RF108`. The ciphertext is not decrypted and is not hashed. |
| Symlink in a directory or ZIP, including a link whose target normalizes outside the root | `RF101`, plus `RF103` when the directory link target leaves the root. The target is not opened. A symlink given as the scan root is refused with exit 2 instead of being followed. |
| FIFO, socket, or device | `RF102`. The node is not read. |
| Directory file replaced, truncated, or extended during the read | `RF109`. The digest is discarded. On a ZIP, `RF109` is only the archive itself changing during the scan (finding path `.`). A declared member size that `zipfile` cannot stream raises a CRC or EOF error and is reported as `RF112`, not `RF109`. |
| Per-file or total uncompressed size over the policy limit | `RF110` and `RF111`. Each read is capped at the remaining budget plus one byte. Bytes returned to the scanner count toward the total, including a chunk that then trips the limit, and the total latch stops later reads. |
| Private-key PEM block | `RF201`. Public certificates and public keys are not this rule. |
| Glassboard bearer shape (`Authorization: Bearer` plus 20 or more url-safe characters, or `gb_` / `gbt_` plus 24 or more) | `RF202`. |
| GitHub token shape (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` of 36 to 255 characters, or `github_pat_` of at least 22) | `RF203`. |
| OpenAI key shape (`sk-proj-`, `sk-svcacct-`, `sk-admin-`, the legacy `T3BlbkFJ` form, or `sk-` plus 48 alphanumerics) | `RF204`. |
| `.env` file, other than `*.example`, `*.sample`, `*.template`, `*.dist`, or `*.defaults` basenames listed in the detector | `RF301`. |
| Credential-like names (`id_rsa` without `.pub`, `credentials.json`, `.netrc`, `.p12`, and the other names in `detectors.py`) | `RF302`. |
| `.git`, `.hg`, `.svn`, `.bzr`, or `CVS` directory, or a `.git` pointer file | `RF303`. Children are still visited so size limits apply to them. |
| Editor, OS, and build junk | `RF304`, warning. |
| File larger than `large_file_bytes` | `RF305`, warning. A file over `max_file_bytes` is `RF110` and is not fully hashed. |
| `*.pem`, `*.key`, `.npmrc`, `.pypirc` | `RF307`, warning. The operator must decide whether the material is public. |
| Policy `forbidden_globs` | `RF400` on inventoried files. |
| Hard link (`nlink > 1`) | `RF115`, warning. The same bytes may be reachable outside the tree. |
| Added, removed, or changed bytes after a manifest | `verify` reports `added`, `removed`, or `changed` and exits 1. |

Name and content rules are heuristics. A novel token format, a secret split
across files, an encrypted blob that is not a ZIP encryption flag, or a
renamed key file can pass. A public document that merely discusses a shape
can also trip a rule; the finding says a shape was found and at which line,
not the value.

## Policy and audit

`releasefence/policy.py` accepts only the documented keys. Sizes are positive
integers, booleans are rejected, duplicate JSON keys and non-standard
constants are rejected, and an ignore `rule_id` must be a known scanner rule
or `RF400`. Globs are case-sensitive `fnmatchcase` patterns; `*` matches `/`.

Suppressed findings move to `suppressions` and keep their original `blocking`
flag plus the matching `suppression` entries. They do not affect the
report's top-level `blocking` flag. A manifest is still refused when any
inventoried file lacks a full SHA-256, including when the size-limit finding
was suppressed, so a policy cannot launder an unreadable file into a
verifiable manifest.

## Manifests

`manifest` writes only when the report is not blocking. The file is a
schema-1 list of relative `path`, `size`, and lowercase SHA-256. Publication
is a flushed temporary file in the destination directory plus `os.link`,
which will not replace an existing path. The destination must be outside a
directory input. Filesystems without hard links fail with exit 2.

The manifest is an unsigned inventory. Anyone who can replace it can point
`verify` at a different baseline. Store it with the same care as the release
approval. `verify` checks the schema before comparing records and treats
inventory drift as blocking even when a policy would hide a content rule.

## Limitations

- Directory scanning requires POSIX directory descriptors and no-follow
  support: `os.open` with `O_DIRECTORY` and `O_NOFOLLOW`, `os.scandir` on
  that descriptor, and `dir_fd` opens for children. Validation was performed
  on Linux with Python 3.11. Windows directory scanning is not supported.
- `zipfile` loads central-directory metadata in memory. File-byte limits do
  not bound archive member count, metadata memory, or overall processing time.
  Apply operating-system resource limits for highly adversarial archives.
- The stream counter counts bytes `read()` returns. A chunk that then trips
  `RF110` or `RF111` counts, and the total latch stops later reads. Bytes
  that `zipfile` decompresses and discards when CRC or header validation
  fails inside that call are not visible to the counter; the member is still
  blocking (`RF112`). Each read request is capped at the remaining budget.
- ZIP symlink and special-file detection uses the Unix mode in
  `external_attr` when `create_system` is Unix. A member with no file-type
  bits is treated as a regular file.
- A trailing-slash name is a directory only when it is not already a symlink
  or other special type. Those types are reported instead of being skipped.
- After `RF111`, later files may appear with a null digest and no separate
  finding. The report is blocking, and manifest publication will not accept
  the null digest.
- Nested archives are ordinary files. Member names inside them are not
  inventory paths. A stored (uncompressed) inner member is visible to the
  byte scanner, so a secret shape in that payload can be reported. A
  deflated inner member is opaque compressed bytes, and the scanner does
  not decompress it to look for secrets.
- Token rules are anchored with a leading word boundary (`\b`). A shape
  glued directly to a preceding word character, such as ZIP local-header
  bytes immediately before `sk-proj-`, is not reported. A separated value
  on its own line is reported.
- The scanner does not look for every credential dialect, does not parse
  document formats, and does not judge whether a PEM block is passwordless.
- `large_file_bytes` may be set above `max_file_bytes`. The hard limit wins
  and the warning threshold then does not apply to rejected files that were
  not recorded with a size above the warning threshold. Over-limit files that
  are recorded use the declared size for `RF305`.
- Scanning the ReleaseFence checkout will flag `fixtures/unsafe` on purpose.
  Those strings are synthetic fixtures, not live credentials.

## Sample fixtures

- `fixtures/safe` is an ordinary tree: source, a license note, a public
  certificate, and `.env.example`. `releasefence scan fixtures/safe` exits 0.
- `fixtures/unsafe` mixes synthetic tokens, a fake private-key PEM, a `.pem`
  certificate name, editor junk, and a symlink that points outside the tree.
  The scan exits 1 and the report does not echo the fixture secrets.
- `fixtures/bad-archive.zip` contains duplicate, absolute, traversal, and
  backslash member names plus one ordinary file. It is blocking and is not
  extracted.

## Out of scope

Malware execution, vulnerability discovery in source code, reproducible
builds, package signature verification, and network calls. Runtime
dependencies are the Python 3.11 standard library only.

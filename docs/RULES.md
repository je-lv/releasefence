# ReleaseFence rules

Generated from `releasefence/model.py` by `scripts/gen_rules_doc.py`. Do not edit by hand.

Errors block: `scan` exits 1 and `manifest` refuses to write. Warnings are reported but do not block. A policy can suppress any rule for named paths; suppressions are listed in the JSON report.

| ID | Severity | Title |
|---|---|---|
| [RF101](#rf101) | error | symbolic link |
| [RF102](#rf102) | error | special file type (device, socket, FIFO or unknown) |
| [RF103](#rf103) | error | path escapes the input root |
| [RF104](#rf104) | error | absolute archive member path |
| [RF105](#rf105) | error | '..' traversal in archive member path |
| [RF106](#rf106) | error | backslash in path |
| [RF107](#rf107) | error | duplicate archive member name |
| [RF108](#rf108) | error | encrypted archive member |
| [RF109](#rf109) | error | file changed while being read |
| [RF110](#rf110) | error | file exceeds per-file size limit |
| [RF111](#rf111) | error | input exceeds total size limit |
| [RF112](#rf112) | error | unreadable or corrupt entry |
| [RF113](#rf113) | error | control, bidi or undecodable characters in path |
| [RF114](#rf114) | error | directory nesting too deep |
| [RF115](#rf115) | warning | hard-linked file |
| [RF116](#rf116) | error | archive member name normalizes to the archive root |
| [RF201](#rf201) | error | private key PEM block |
| [RF202](#rf202) | error | Glassboard bearer token |
| [RF203](#rf203) | error | GitHub token |
| [RF204](#rf204) | error | OpenAI API key |
| [RF301](#rf301) | error | environment (.env) file |
| [RF302](#rf302) | error | credential-like file name |
| [RF303](#rf303) | error | version-control internals |
| [RF304](#rf304) | warning | editor, OS or build junk |
| [RF305](#rf305) | warning | unexpectedly large file |
| [RF307](#rf307) | warning | possible credential file |
| [RF400](#rf400) | error | file matches a policy forbidden glob |

## RF101

**Symbolic link** (error)

A directory entry or ZIP member is a symbolic link. ReleaseFence never follows links, so the content behind it was not inspected, and an extractor may write through it.

**Fix:** Replace the link with the file it points to, or remove it.

## RF102

**Special file type (device, socket, FIFO or unknown)** (error)

A device, socket, FIFO or other non-regular file. These have no place in a source release and some extractors recreate them.

**Fix:** Remove it from the release.

## RF103

**Path escapes the input root** (error)

A path or symbolic link target resolves outside the input root.

**Fix:** Remove the entry; a release must be self-contained.

## RF104

**Absolute archive member path** (error)

A ZIP member name is absolute, so a naive extractor writes it anywhere on disk.

**Fix:** Rebuild the archive with relative member names.

## RF105

**'..' traversal in archive member path** (error)

A ZIP member name contains a `..` segment (path traversal, "zip slip").

**Fix:** Rebuild the archive without `..` in member names.

## RF106

**Backslash in path** (error)

A path contains a backslash: a separator on Windows, an ordinary character on POSIX. The same archive extracts to different trees on different systems.

**Fix:** Use forward slashes only.

## RF107

**Duplicate archive member name** (error)

Two ZIP members normalize to the same path, or a path is both a file and a directory. Extractors disagree on which copy wins, so a reviewer may inspect a different file from the one that gets installed.

**Fix:** Rebuild the archive so every normalized path appears once.

## RF108

**Encrypted archive member** (error)

An encrypted ZIP member. Its content cannot be inspected.

**Fix:** Publish without encryption, or inspect the content separately.

## RF109

**File changed while being read** (error)

A file or directory changed while it was being read: its size, metadata or type differed between checks. The report cannot vouch for it.

**Fix:** Scan again when nothing is writing to the input.

## RF110

**File exceeds per-file size limit** (error)

A file exceeds the per-file size limit and was not read. Default 10 MiB; set `max_file_bytes` in a policy.

**Fix:** Check whether the file belongs in the release, or raise the limit.

## RF111

**Input exceeds total size limit** (error)

The input exceeds the total size limit; scanning stopped. Default 100 MiB; set `max_total_bytes` in a policy.

**Fix:** Check the input, or raise the limit.

## RF112

**Unreadable or corrupt entry** (error)

An entry could not be listed, opened or read, or a ZIP entry is corrupt.

**Fix:** Fix permissions or rebuild the archive, then scan again.

## RF113

**Control, bidi or undecodable characters in path** (error)

A path contains control, bidirectional-override or undecodable characters. These can hide or disguise names in terminals and code review. The path is shown escaped.

**Fix:** Rename the file.

## RF114

**Directory nesting too deep** (error)

Directories are nested deeper than 256 levels; deeper levels were not scanned.

**Fix:** Flatten the tree.

## RF115

**Hard-linked file** (warning)

A file has more than one hard link, so its content may be shared with a file outside the release.

**Fix:** Confirm the content is meant to ship, or copy the file instead of linking it.

## RF116

**Archive member name normalizes to the archive root** (error)

A ZIP member name normalizes to the archive root (for example `.` or `/`) and names no file.

**Fix:** Rebuild the archive without that member.

## RF201

**Private key PEM block** (error)

A PEM `PRIVATE KEY` block. The report gives the line number, never the key.

**Fix:** Remove the key from the release and rotate it.

## RF202

**Glassboard bearer token** (error)

A bearer token in an `Authorization` header or the `gbt_` token format. The report gives the line number, never the token.

**Fix:** Remove the token and revoke it.

## RF203

**GitHub token** (error)

A GitHub token (`ghp_`, `gho_`, `ghu_`, `ghs_`, `ghr_` or `github_pat_`). The report gives the line number, never the token.

**Fix:** Remove the token and revoke it in GitHub.

## RF204

**OpenAI API key** (error)

An OpenAI API key. The report gives the line number, never the key.

**Fix:** Remove the key and revoke it.

## RF301

**Environment (.env) file** (error)

A `.env` file (or `.env.*`, `*.env`). These usually hold real settings and secrets. Templates such as `.env.example` are allowed.

**Fix:** Publish a template such as `.env.example` instead.

## RF302

**Credential-like file name** (error)

A file name that is almost always a credential: SSH private keys, `.netrc`, `.git-credentials`, `credentials.json`, keystores, `.p12`, `.pfx` and similar.

**Fix:** Remove it from the release.

## RF303

**Version-control internals** (error)

Version-control internals such as `.git`, `.hg` or `.svn`. They can carry full history, including removed secrets.

**Fix:** Package from an export, not from the working copy.

## RF304

**Editor, OS or build junk** (warning)

Editor, operating-system or build leftovers: `.DS_Store`, swap files, `__pycache__`, backup files and similar.

**Fix:** Remove them, or add them to the packaging ignore list.

## RF305

**Unexpectedly large file** (warning)

A file larger than the large-file threshold. Default 5 MiB; set `large_file_bytes` in a policy.

**Fix:** Confirm it belongs in the release.

## RF307

**Possible credential file** (warning)

A `.pem` or `.key` file, or a tool config that often holds credentials (`.npmrc`, `.pypirc`). Public certificates are fine; private keys are not.

**Fix:** Open it and confirm it is meant to be public.

## RF400

**File matches a policy forbidden glob** (error)

A file matches a `forbidden_globs` pattern in your policy.

**Fix:** Remove the file, or change the policy.


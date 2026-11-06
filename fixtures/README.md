# Sample inputs

- `safe/`: a small release that scans clean.
- `unsafe/`: one example of most publication mistakes. It is meant to be blocked.
- `bad-archive.zip`: a ZIP with path traversal, an absolute name, a backslash name and a
  duplicate member.

Every secret in `unsafe/` is synthetic and has never been valid: the tokens are runs of one
repeated letter and the private key body is not a key. They exist only so the rules have
something to match. `../releasefence.json` suppresses exactly these findings, in a Git checkout, the source
archives and the wheel, so the project's own release scans clean. Its patterns start with `*`
so they also match inside a ZIP whose files sit under a top-level folder.

Source distributions replace the `outside-link` symbolic link with a copy of its target, so
that sample only demonstrates the symlink rules in a Git checkout.

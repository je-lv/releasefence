# Origin

ReleaseFence was built during the early test runs of
[Glassboard](https://github.com/je-lv/glassboard), a self-hosted coordination board where AI
agents work under human supervision. This page records what the agents were asked, what the
run was testing, how the result was reviewed, and what changed before this release.

## The run

On 2026-10-13 three AI coding agents from three different companies, OpenAI's Codex,
Anthropic's Claude Code and xAI's Grok, joined one Glassboard session. They were three separate
products running as three separate programs, each in its own sandbox with its own home
directory and its own Glassboard identity. They were not subagents of one assistant: no agent
launched or controlled another, even after they chose Codex as their lead. They exchanged
messages only through the board, and the only other thing they shared was the project's Git
repository. They received the same written instruction and the same brief, both quoted below, and nothing else. No human assigned
their work: through the board they chose the architecture, a lead, their roles and the task
split, reviewed each other's submissions against exact Git commits, uploaded their evidence,
and submitted the finished project for human review.

The human wrote the specification: what ReleaseFence must detect, the policy file, the
manifest and verify commands, and the exit codes. The agents designed and built everything
else. That is also why ReleaseFence detects Glassboard tokens (rule RF202): the brief asked
for it.

## What the run was testing

The run tested Glassboard, not ReleaseFence. Its purpose was Glassboard's then-new file
sharing: whether agents would use it, unprompted by a human, to hand over real work.

- **Shared files.** Each agent had to upload at least one useful file to the session's shared
  files: a test result, design note or review report. Uploaded files cannot be changed
  afterwards, and Glassboard never renders or executes them. File sharing had been added to
  Glassboard the day before.
- **Final deliverables.** The team had to place the finished source ZIP, test report and issue
  log in the shared files' *Final deliverables* section, kept apart from supporting evidence
  for the human reviewer. That section was added the same day, minutes before the run.

To make the file sharing carry real weight, the run used a complete project with no human
dividing the work, and so also exercised the rest of the board:

- **Self-organization.** Each agent picked its work with `glassboard task next`, recorded its
  role, worked on a linked task, and left a structured checkpoint before it stopped.
- **Reviews bound to evidence.** Every peer review named the exact submission and Git commit it
  approved, so an approval could not drift onto later code.
- **Human authority.** Only the human operator could accept the root task.
- **Honest friction.** The agents had to record every Glassboard problem they met. One of
  them, a message whose text was rejected as a command-line argument, led to the `--body` and
  `--body-file` options Glassboard added the next day.

## The exact instruction

Each agent was started with this message. It is quoted from the Codex launch; the Claude Code
and Grok messages differ only in the agent names. The local folder path is replaced with
`[project directory]`.

> You are the real codex coding client, @operator/releasefence-codex, in Glassboard session releasefence-autonomy. Work only in [project directory]. Read GOAL.md and AGENTS.md and `glassboard protocol`, run `glassboard use releasefence-autonomy`, then sync the session. Coordinate with the other selected agents (claude, grok) through Glassboard. Choose the architecture, lead, job roles, work split, dependencies, reviews, and implementation process yourselves. Record decisions, handoffs, blockers, and task progress on the board. Meet every Autonomous process acceptance item in GOAL.md, including each agent upload, exact reviews, checkpoints, delivery files and GLASSBOARD-ISSUES.md. The human will perform final review and acceptance; submit root T1 when ready. Do not access external accounts, change credentials, or leave this project.
>
>
> PROJECT BRIEF
>
> *(the full `GOAL.md` below)*

### GOAL.md

> # ReleaseFence
>
> Build **ReleaseFence**, an offline command-line tool that inspects a source release directory or ZIP before publication and produces a deterministic security and integrity report.
>
> ## Required behavior
>
> - Python 3.11 or newer. Runtime uses only the standard library and works without network access.
> - `releasefence scan PATH` accepts a directory or ZIP and emits a concise text report. `--format json` emits a stable machine-readable report. Exit 0 means no blocking findings; exit 1 means the scan completed with blocking findings; exit 2 means input or usage failed.
> - Recursively inventory ordinary files with normalized relative paths, byte sizes and SHA-256 digests. Output ordering must be deterministic.
> - For ZIP inputs, reject or report duplicate member names, absolute paths, `..` traversal, backslash ambiguity, encrypted members, symlinks and special file types. Enforce configurable per-file and total uncompressed-size limits while streaming; do not extract the archive.
> - For directory inputs, do not follow symlinks. Report symlinks, sockets, devices and path escapes as blocking findings. Detect files that change while being read by comparing actual streamed size and stable metadata.
> - Detect likely publication mistakes: private-key PEM blocks; Glassboard bearer-token shapes; common GitHub and OpenAI token shapes; `.env` and credential-like file names; Git internals; editor/OS junk; and unexpectedly large files. Do not print secret values. Each finding needs a stable rule ID, severity, path and useful explanation.
> - Accept an optional JSON policy file that can set size limits, add forbidden glob patterns and ignore named rule IDs for named path globs. Validate it strictly and document the schema. Policy suppressions must be represented in JSON output so an audit can see what was ignored.
> - `releasefence manifest PATH --out FILE` writes an atomic JSON manifest for a clean input. Refuse to overwrite an existing output. A subsequent `releasefence verify PATH --manifest FILE` must detect additions, removals and content changes.
> - Keep errors concise. Never execute, import, render or extract inspected content.
>
> ## Deliverables
>
> A runnable package, source code, automated tests, sample safe and unsafe fixtures, README quickstart, threat model and design notes, and `GLASSBOARD-ISSUES.md` recording every Glassboard workflow issue encountered or explicitly saying none were observed. Final deliverables must include a source ZIP and a test/report artifact suitable for human review.
>
> ## Autonomous process acceptance
>
> The selected agents decide the architecture, lead, job roles, task split, dependencies, reviewers and integration method through Glassboard. No human assigns their internal work.
>
> Each agent must:
>
> 1. use `glassboard task next` when selecting work and record its role on the board;
> 2. create or work on a linked task and leave a structured checkpoint before its process stops;
> 3. upload at least one useful immutable file to the session Artifacts area (a test result, design note, review report or other real evidence);
> 4. bind peer review to the exact submission event and Git commit;
> 5. record coordination and any product issue on Glassboard.
>
> The integrated source ZIP, final test report and `GLASSBOARD-ISSUES.md` must be uploaded with `artifact upload --deliverable`. The root task is submitted for human review and can only be accepted by the human operator. Work is confined to this directory and the local Glassboard session. Do not access email, cloud accounts, credentials, unrelated files or external targets. Do not publish or push to a remote service.

### AGENTS.md

> # ReleaseFence agent boundary
>
> Read `GOAL.md` and use the Glassboard session named in your launch prompt as the canonical coordination record. Work only in this repository. Network access is for the local Glassboard service and package metadata only; the implementation itself is offline and standard-library only. Do not access external accounts, email, unrelated workspaces, credentials or external security targets. Do not publish or push to a remote service.

## Human review

The agents submitted the project. The human reviewer reproduced a bug and returned it with
this note:

> Human review found a blocking ZIP path-collision gap at submitted commit f4c8909b5002c1ecb72779a3ad82488f67d7ac03. Reproduction: create a ZIP with members `same` and `same/`; `python3.11 -m releasefence scan FILE --format json` exits 0 with no RF107 finding. A ZIP with the single member `.` also exits 0. Treat normalized archive paths as one namespace regardless of file/directory type; reject empty/dot-normalized member paths; add regression tests and update docs if needed. Rebuild and re-upload all three final deliverables, repeat exact-commit peer review, and resubmit T1. Also verify installation in an isolated environment and record the exact supported install procedure; my no-build-isolation venv lacked the `wheel` command, so distinguish missing local build tooling from a package defect in the report.

Each agent was then restarted with this message:

> Continue your existing ReleaseFence conversation after human return event #204. Read the current Glassboard session and shared project before acting. Coordinate with peers and continue toward the original GOAL.md brief and correct every issue in human note #203. This is an automatic process continuation; there are no new human requirements. Stop when T1 is submitted for human review.

The agents fixed the bug, added regression tests, documented the tested installation
procedure, repeated the peer review against the new commit, and resubmitted. The human
accepted the result at commit `66fb9a6`, the starting point of this repository.

## Why it was polished before release

The brief asked for a working, tested tool for one human to review, not a public project.
Before publishing it, a separate session directed by the maintainer found and fixed:

- **A test bug.** One test failed on Python 3.12 because a test left a socket open, and two
  socket tests were silently skipped when the temporary directory path was long. The tool
  itself was not affected.
- **Hard-to-read output.** The text report was one flat list with the same advice repeated
  on every secret. It is now grouped by file with the verdict last, and `-v` explains each rule.
- **Missing publication pieces.** There was no licence, no rules reference and no policy
  example, the packaging used older metadata, and the repository held the agents' coordination
  records, which are not part of the tool.
- **Untested Python versions.** It had been tested on Python 3.11 and 3.12 only; it now passes
  on 3.11, 3.12, 3.13 and 3.14.

The scanner, its rules and its checks are the agents' work. Apart from shorter finding
messages, the changes are in presentation, documentation, packaging and tests.

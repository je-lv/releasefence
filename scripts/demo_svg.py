#!/usr/bin/env python3
"""Render a ReleaseFence run as the README terminal image.

Development tool only: it needs `rich` (pip install rich), which ReleaseFence
itself never uses. Run from the repository root:
    python scripts/demo_svg.py docs/demo-scan.svg
"""
import os
import subprocess
import sys

from rich.console import Console
from rich.terminal_theme import MONOKAI
from rich.text import Text

ARGS = ["scan", "fixtures/unsafe"]
TITLE = "releasefence: scan of the bundled unsafe sample"


def main(out_path):
    env = dict(os.environ, FORCE_COLOR="1")
    env.pop("NO_COLOR", None)
    output = subprocess.run([sys.executable, "-m", "releasefence", *ARGS], env=env,
                            capture_output=True, text=True).stdout
    console = Console(record=True, width=100, file=open(os.devnull, "w"), force_terminal=True,
                      color_system="truecolor")
    # Prompt styled like a highlighted shell line: "$" and the target in bold
    # green, the command itself plain.
    prompt = Text()
    prompt.append("$", style="bold #98e024")
    prompt.append(" releasefence " + " ".join(ARGS[:-1]) + " ")
    prompt.append(ARGS[-1], style="bold #98e024")
    console.print(prompt)
    console.print(Text.from_ansi(output.rstrip("\n")))
    console.save_svg(out_path, title=TITLE, theme=MONOKAI)


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "docs/demo-scan.svg")

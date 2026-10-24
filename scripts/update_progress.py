"""Recompute the README progress block from the TODO checkboxes. Usage: python scripts/update_progress.py"""

import datetime as dt
import re
from pathlib import Path

README = Path(__file__).resolve().parent.parent / "README.md"
WIDTH = 20


def main() -> None:
    text = README.read_text()
    todo = text.split("## TODO", 1)[1]
    phases = []
    for block in re.split(r"^### ", todo, flags=re.M)[1:]:
        title = block.splitlines()[0].strip()
        boxes = re.findall(r"^- \[([ x])\]", block, flags=re.M)
        phases.append((title, boxes.count("x"), len(boxes)))

    done, total = sum(p[1] for p in phases), sum(p[2] for p in phases)
    pad = max(len(p[0]) for p in phases) + 2
    lines = []
    for title, d, n in phases:
        filled = round(WIDTH * d / n)
        lines.append(f"{title:<{pad}}{'█' * filled}{'░' * (WIDTH - filled)}  {round(100 * d / n):>3}% ({d}/{n})")
    block = "```\n" + "\n".join(lines) + "\n```"

    text = re.sub(r"\*\*Overall: \d+%\*\* \(\d+ of \d+ tasks\)",
                  f"**Overall: {round(100 * done / total)}%** ({done} of {total} tasks)", text)
    text = re.sub(r"```\nPhase 0.*?```", lambda _: block, text, count=1, flags=re.S)
    text = re.sub(r"\*Last updated: [\d-]+\*", f"*Last updated: {dt.date.today()}*", text)
    README.write_text(text)
    print(f"{done}/{total}")


if __name__ == "__main__":
    main()

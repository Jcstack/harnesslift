"""Render the allowlisted result of an owned, real-provider coding check.

This is a summary card, not a recording of the Claude Code interface.
No runtime directories, credentials, transcripts or screenshots are read.
"""

import json
from pathlib import Path
import re

from PIL import Image, ImageDraw

from build_brand_assets import BG, PANEL, INK, MUTED, MINT, CORAL, font


ROOT = Path(__file__).resolve().parent
FIELDS = {"format", "kind", "route", "client", "client_version", "execution",
          "requested_model", "requested_effort", "project_api_used", "example",
          "initial_tests", "initial_failures", "final_tests_passed", "tests_unchanged",
          "tools_observed", "runtime_reconfigured", "presentation", "scope"}


def main():
    value = json.loads((ROOT / "provider-check.json").read_text())
    if (set(value) != FIELDS or value["kind"] != "real-provider-owned-task"
            or value["project_api_used"] is not False or value["tests_unchanged"] is not True
            or value["runtime_reconfigured"] is not False
            or value["execution"] != "headless" or value["requested_effort"] != "high"
            or value["initial_tests"] != 5 or value["initial_failures"] != 3
            or value["final_tests_passed"] != 5
            or value["tools_observed"] != ["Bash", "Edit", "Read"]
            or not re.fullmatch(r"gpt-[a-z0-9.-]+", value["requested_model"])
            or not re.fullmatch(r"\d+\.\d+\.\d+", value["client_version"])):
        raise RuntimeError("The owned provider-check receipt is not the reviewed result")

    image = Image.new("RGB", (1280, 494), BG)
    draw = ImageDraw.Draw(image)
    draw.text((48, 29), "REAL PROVIDER CHECK", font=font(19, bold=True), fill=MINT)
    draw.text((48, 72), "Claude Code tools. Codex model.", font=font(42, bold=True), fill=INK)
    draw.text((48, 130), "Requested: " + value["requested_model"] + "  /  high effort",
              font=font(23), fill=MUTED)
    draw.text((48, 166), "Claude Code " + value["client_version"] + "  /  HarnessLift subscription route",
              font=font(21), fill=MUTED)

    for x, title, big, detail, color in (
            (48, "STARTING EXERCISE", "3 failing", "5 existing tests", CORAL),
            (454, "AFTER THE MODEL EDIT", "5 passing", "Tests unchanged", MINT),
            (860, "LOCAL TOOLS OBSERVED", "Read · Edit · Bash", "Real headless Claude Code", MINT)):
        draw.rounded_rectangle((x, 231, x + 372, 390), radius=16, fill=PANEL)
        draw.text((x + 22, 251), title, font=font(15, bold=True), fill=MUTED)
        draw.text((x + 22, 290), big, font=font(27 if x == 860 else 37, bold=True), fill=color)
        draw.text((x + 22, 348), detail, font=font(19), fill=INK)

    draw.text((48, 418), "Try it: examples/first-task  ·  Model requests and task context reach OpenAI",
              font=font(19), fill=MUTED)
    draw.text((48, 454), "Rendered verification summary · One small macOS task · Not a recording or benchmark",
              font=font(17), fill=MUTED)
    image.save(ROOT / "provider-check.png", optimize=True)
    print("Rendered the reviewed real-provider summary; no runtime data read")


if __name__ == "__main__":
    main()

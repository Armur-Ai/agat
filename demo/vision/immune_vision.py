#!/usr/bin/env python3
"""
agat — the adaptive immune system: a VISION film.

A cinematic, animated depiction of agat's five immune properties operating at
full strength. This is a concept/vision piece, not the shipping CLI — every
scene carries a dim "VISION" marker, and the real `agat` binary gains no such
commands. Intended to be recorded with VHS (demo/vision/vision.tape) and
narrated on stage as "how it's expected to run".

  python3 demo/vision/immune_vision.py          # play the whole film
  python3 demo/vision/immune_vision.py <scene>   # one scene (title/germinal/
                                                 # forecaster/herd/living/
                                                 # cytokine/close)
"""
import sys
import math
import time
import random

random.seed(7)

# ---- 24-bit palette (agat brand) -------------------------------------
CYAN = (94, 242, 255)
PERI = (143, 168, 255)
VIOLET = (208, 123, 255)
GREEN = (46, 204, 113)
YELLOW = (255, 200, 87)
RED = (255, 92, 122)
GREY = (120, 134, 166)
DGREY = (70, 80, 104)
WHITE = (226, 236, 255)

W = 74  # content width
SPEED = 1.5  # global pacing multiplier (higher = slower, more cinematic)


def fg(rgb, s):
    r, g, b = rgb
    return f"\x1b[38;2;{r};{g};{b}m{s}\x1b[0m"


def bold(s):
    return f"\x1b[1m{s}\x1b[0m"


def dim(s):
    return f"\x1b[2m{s}\x1b[0m"


def vlen(s):
    """Visible length (strip ANSI)."""
    out, i = 0, 0
    while i < len(s):
        if s[i] == "\x1b":
            while i < len(s) and s[i] != "m":
                i += 1
            i += 1
        else:
            out += 1
            i += 1
    return out


class Screen:
    """Flicker-free full-screen renderer: home the cursor and overwrite."""

    def __init__(self, height=24):
        self.height = height
        sys.stdout.write("\x1b[?25l")  # hide cursor
        sys.stdout.write("\x1b[2J")
        sys.stdout.flush()

    def draw(self, lines, hold=0.0):
        buf = ["\x1b[H"]
        for i in range(self.height):
            s = lines[i] if i < len(lines) else ""
            pad = self.height and max(0, W + 2 - vlen(s))
            buf.append(" " + s + " " * pad + "\x1b[K")
            if i < self.height - 1:
                buf.append("\r\n")
        sys.stdout.write("".join(buf))
        sys.stdout.flush()
        if hold:
            time.sleep(hold * SPEED)

    def close(self):
        sys.stdout.write("\x1b[?25h\x1b[0m\r\n")
        sys.stdout.flush()


def bar(frac, width, color, empty=DGREY, full="█", void="░"):
    frac = max(0.0, min(1.0, frac))
    n = int(round(frac * width))
    return fg(color, full * n) + fg(empty, void * (width - n))


def center(s, width=W):
    pad = max(0, (width - vlen(s)) // 2)
    return " " * pad + s


def ease(t):
    return 1 - (1 - t) * (1 - t)


# ---- shared chrome ---------------------------------------------------
def header(num, title, biology, accent):
    line = []
    line.append(
        bold(fg(accent, f"  {num}  ")) + bold(fg(WHITE, title))
    )
    tag = dim(fg(VIOLET, "◇ VISION"))
    pad = max(1, W - vlen(line[0]) - vlen(tag))
    head = line[0] + " " * pad + tag
    rule = fg(DGREY, "  " + "─" * (W - 2))
    sub = dim(fg(GREY, "  " + biology))
    return [head, sub, rule, ""]


def hexid(n=12):
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


def scene_frame(sc, head, body, footer_note, accent, frames, fps=22, builder=None):
    """Run `frames` animation steps; builder(i) returns body lines."""
    dt = 1.0 / fps
    for i in range(frames):
        lines = list(head)
        lines += builder(i)
        # pad to footer
        while len(lines) < sc.height - 2:
            lines.append("")
        lines.append(fg(DGREY, "  " + "─" * (W - 2)))
        lines.append(dim(fg(GREY, "  " + footer_note)))
        sc.draw(lines)
        time.sleep(dt * SPEED)


# ======================================================================
# TITLE
# ======================================================================
LOGO = [
    r"  █████╗  ██████╗  █████╗ ████████╗",
    r" ██╔══██╗██╔════╝ ██╔══██╗╚══██╔══╝",
    r" ███████║██║  ███╗███████║   ██║   ",
    r" ██╔══██║██║   ██║██╔══██║   ██║   ",
    r" ██║  ██║╚██████╔╝██║  ██║   ██║   ",
    r" ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ",
]
GRAD = [CYAN, (122, 190, 255), PERI, (170, 150, 255), (197, 130, 255), VIOLET]


def scene_title(sc):
    # fade the logo in row by row
    for reveal in range(len(LOGO) + 1):
        lines = ["", "", ""]
        for r, row in enumerate(LOGO):
            if r < reveal:
                lines.append(center(fg(GRAD[r], row), W))
            else:
                lines.append("")
        while len(lines) < sc.height:
            lines.append("")
        sc.draw(lines, 0.11)
    # title text types in
    tagline = "AN ADAPTIVE IMMUNE SYSTEM FOR BINARIES"
    for k in range(len(tagline) + 1):
        lines = ["", "", ""]
        for r, row in enumerate(LOGO):
            lines.append(center(fg(GRAD[r], row), W))
        lines.append("")
        lines.append(center(bold(fg(PERI, tagline[:k])), W))
        while len(lines) < sc.height:
            lines.append("")
        sc.draw(lines, 0.02)
    # framing marker
    for _ in range(26):
        lines = ["", "", ""]
        for r, row in enumerate(LOGO):
            lines.append(center(fg(GRAD[r], row), W))
        lines.append("")
        lines.append(center(bold(fg(PERI, tagline)), W))
        lines.append("")
        lines.append(center(dim(fg(VIOLET, "▞  a vision of the autonomous immune system  ▞")), W))
        lines.append("")
        lines.append(center(dim(fg(GREY, "five properties · offline · air-gapped · self-evolving")), W))
        while len(lines) < sc.height:
            lines.append("")
        sc.draw(lines, 0.06)


# ======================================================================
# 1 · GERMINAL CENTER — self-play affinity maturation
# ======================================================================
def scene_germinal(sc):
    head = header("①", "THE GERMINAL CENTER", "somatic hypermutation · the system red-teams itself",
                  VIOLET)
    foot = "self-play · synthetic adversary vs. detector repertoire · unattended"
    gens = [
        (0.61, 8, 240_000),
        (0.78, 14, 540_000),
        (0.90, 22, 870_000),
        (0.965, 31, 1_120_000),
        (0.994, 40, 1_284_301),
    ]
    stream = [hexid(10) for _ in range(6)]

    def builder(i):
        t = i / 110.0
        gi = min(len(gens) - 1, int(t * len(gens)))
        cov, det, nvar = gens[gi]
        # within-gen eased progress toward this gen's coverage
        local = (t * len(gens)) - gi
        prev = gens[gi - 1][0] if gi > 0 else 0.30
        shown = prev + (cov - prev) * ease(min(1.0, local * 1.4))
        nv = int(nvar * min(1.0, (i + 1) / 110.0))
        rows = []
        rows.append("  " + fg(PERI, "mutator") + dim(fg(GREY, "  synthesizing adversarial antigens")))
        rows.append("    " + dim(fg(GREY, "variants generated  ")) + bold(fg(WHITE, f"{nv:>10,}")))
        rows.append("")
        # stream of variants, caught vs evaded
        for k in range(6):
            if (i + k) % 7 == 0:
                stream[k] = hexid(10)
            evade = ((i // 3) + k) % 5 == 0 and shown < 0.99
            mark = fg(RED, "✗ evaded ") if evade else fg(GREEN, "✓ caught ")
            kind = random.choice(["poly", "meta", "ai-rw", "poly+meta"])
            rows.append("    " + mark + fg(DGREY, stream[k]) + dim(fg(GREY, f"  {kind}")))
        rows.append("")
        rows.append("  " + fg(CYAN, f"generation {gi+1}/5") + dim(fg(GREY, "   hypermutate → negative-select → clone")))
        rows.append("    " + "coverage  " + bar(shown, 34, GREEN) + bold(fg(WHITE, f"  {shown*100:5.1f}%")))
        rows.append("    " + dim(fg(GREY, "detectors ")) + fg(VIOLET, "▮" * det) + dim(fg(GREY, f"  {det}")))
        return rows

    scene_frame(sc, head, None, foot, VIOLET, 120, fps=22, builder=builder)
    # final stamp
    head2 = header("①", "THE GERMINAL CENTER", "somatic hypermutation · the system red-teams itself", VIOLET)
    for _ in range(26):
        rows = []
        rows.append("")
        rows.append(center(bold(fg(GREEN, "▰  COVERAGE SEALED  ▰")), W))
        rows.append("")
        rows.append(center("coverage  " + bar(0.994, 34, GREEN) + bold(fg(WHITE, "  99.4%")), W))
        rows.append("")
        rows.append(center(dim(fg(GREY, "1,284,301 synthetic attacks absorbed overnight · 0 analysts")), W))
        rows.append(center(dim(fg(PERI, "the attacks that would beat it tomorrow are tonight's training set")), W))
        lines = list(head2) + rows
        while len(lines) < sc.height - 2:
            lines.append("")
        lines.append(fg(DGREY, "  " + "─" * (W - 2)))
        lines.append(dim(fg(GREY, "  " + "every variant stays inert · antigen space only · never a weapon")))
        sc.draw(lines, 0.055)


# ======================================================================
# 2 · VACCINE FORECASTER — immunize before the strain is written
# ======================================================================
def scene_forecaster(sc):
    head = header("②", "THE VACCINE FORECASTER", "strain forecasting · memory before the first encounter", CYAN)
    foot = "project the mutation space forward · pre-build memory cells"
    branches = ["recompiled", "re-encrypted", "obfuscated", "LLM-rewritten", "packed+LLM"]

    def builder(i):
        t = min(1.0, i / 70.0)
        rows = []
        rows.append("  " + fg(PERI, "known family") + "  " + bold(fg(WHITE, "ransom.aux")) + dim(fg(GREY, "   projecting drift →")))
        rows.append("")
        grown = int(t * len(branches))
        for b in range(len(branches)):
            if b < grown:
                depth = int(ease(min(1.0, t * 1.3)) * 22)
                twig = fg(DGREY, "·" * depth)
                node = fg(CYAN, "◆")
                rows.append("    " + dim(fg(GREY, "└─")) + twig + node + dim(fg(GREY, f"  future: {branches[b]}")))
            else:
                rows.append("")
        rows.append("")
        pre = int(2847 * t)
        rows.append("  " + fg(VIOLET, "synthesizing attenuated antigens along each trajectory"))
        rows.append("    " + dim(fg(GREY, "memory cells pre-built  ")) + bold(fg(WHITE, f"{pre:>5,}")) + "  " + bar(t, 24, VIOLET))
        return rows

    scene_frame(sc, head, None, foot, CYAN, 76, fps=22, builder=builder)
    # the real variant lands months later -> instant catch
    head2 = header("②", "THE VACCINE FORECASTER", "strain forecasting · memory before the first encounter", CYAN)
    msgs = [
        (RED, "  +6 months later: a brand-new variant arrives, byte-for-byte unseen"),
        (GREY, "    scanning …"),
        (GREEN, "    ✓ falls straight into a pre-built memory cell — secondary response"),
        (GREEN, "    ✓ MALICIOUS · family ransom.aux · affinity 0.91 · 0 ms first-contact"),
    ]
    for step in range(len(msgs) + 22):
        rows = [""]
        for m in range(min(step, len(msgs))):
            col, s = msgs[m]
            rows.append(fg(col, s))
        if step >= len(msgs):
            rows.append("")
            rows.append(center(bold(fg(CYAN, "immunized against 2,847 strains no one has written yet")), W))
        lines = list(head2) + rows
        while len(lines) < sc.height - 2:
            lines.append("")
        lines.append(fg(DGREY, "  " + "─" * (W - 2)))
        lines.append(dim(fg(GREY, "  coverage of the reachable mutation space — a head start, not a guess")))
        sc.draw(lines, 0.14 if step < len(msgs) else 0.05)


# ======================================================================
# 3 · HERD IMMUNITY — one node teaches the fleet
# ======================================================================
def scene_herd(sc):
    head = header("③", "HERD IMMUNITY", "population memory · ship antibodies, not data", GREEN)
    foot = "signed antibody pack · no samples · no telemetry · air-gapped"
    ROWS, COLS = 7, 24
    cx, cy = 4, 3  # patient zero

    def grid(state_fn):
        out = []
        for r in range(ROWS):
            line = "   "
            for c in range(COLS):
                line += state_fn(r, c)
            out.append(line)
        return out

    # phase A: patient zero detects
    for i in range(16):
        flash = (i // 2) % 2 == 0
        def sfn(r, c, flash=flash):
            if r == cy and c == cx:
                return fg(RED if flash else YELLOW, "◉") + " "
            return fg(DGREY, "·") + " "
        rows = ["  " + fg(RED, "patient zero") + dim(fg(GREY, "  a node meets a genuinely novel threat")), ""]
        rows += grid(sfn)
        rows += ["", "  " + dim(fg(GREY, "maturing response · signing antibody pack …"))]
        lines = list(head) + rows
        while len(lines) < sc.height - 2:
            lines.append("")
        lines.append(fg(DGREY, "  " + "─" * (W - 2)))
        lines.append(dim(fg(GREY, "  " + foot)))
        sc.draw(lines, 0.07)
    # phase B: propagation pulse
    maxd = max(abs(r - cy) + abs(c - cx) for r in range(ROWS) for c in range(COLS))
    for wave in range(maxd + 10):
        def sfn(r, c, wave=wave):
            d = abs(r - cy) + abs(c - cx)
            if r == cy and c == cx:
                return fg(GREEN, "◉") + " "
            if d < wave - 1:
                return fg(GREEN, "●") + " "
            if d == wave or d == wave - 1:
                return fg(CYAN, "◌") + " "
            return fg(DGREY, "·") + " "
        immune = sum(1 for r in range(ROWS) for c in range(COLS)
                     if (abs(r - cy) + abs(c - cx)) < wave - 1 or (r == cy and c == cx))
        pct = immune / (ROWS * COLS)
        rows = ["  " + fg(GREEN, "signed antibody pack propagating") + dim(fg(GREY, "  — learned immunity, not evidence")), ""]
        rows += grid(sfn)
        rows += ["", "  " + "fleet immune  " + bar(pct, 30, GREEN) + bold(fg(WHITE, f"  {int(pct*ROWS*COLS):>3}/{ROWS*COLS}"))]
        lines = list(head) + rows
        while len(lines) < sc.height - 2:
            lines.append("")
        lines.append(fg(DGREY, "  " + "─" * (W - 2)))
        lines.append(dim(fg(GREY, "  " + foot)))
        sc.draw(lines, 0.06)
    for _ in range(22):
        lines = list(head) + [
            "",
            center(bold(fg(GREEN, "▰  HERD IMMUNIZED  ▰")), W),
            "",
            center("1 node learned  →  " + bold(fg(WHITE, "1,204 nodes immune")) + "  in 0.3 s", W),
            "",
            center(dim(fg(GREY, "0 bytes of sample data left any machine")), W),
            center(dim(fg(PERI, "an attack on one node makes every node stronger")), W),
        ]
        while len(lines) < sc.height - 2:
            lines.append("")
        lines.append(fg(DGREY, "  " + "─" * (W - 2)))
        lines.append(dim(fg(GREY, "  " + foot)))
        sc.draw(lines, 0.055)


# ======================================================================
# 4 · LIVING SELF — continuous tolerance + regulation
# ======================================================================
def scene_living(sc):
    head = header("④", "THE LIVING SELF", "re-tolerization + regulatory T-cells · never frozen", PERI)
    foot = "the benign region breathes with your environment · self-restraint"
    events = [
        (GREEN, "  + new build  app v2.4.1        folded into self ✓"),
        (GREEN, "  + vendor tool oscan-cli         folded into self ✓"),
        (YELLOW, "  ! detector d-7742 drifting onto benign builds  (autoimmune)"),
        (VIOLET, "  ↯ regulatory layer retires d-7742 before it ever fires"),
        (GREEN, "  + internal util  release-bot     folded into self ✓"),
    ]

    def builder(i):
        # breathing self region
        phase = math.sin(i / 7.0) * 0.5 + 0.5
        radius = int(10 + phase * 6)
        rows = []
        rows.append("  " + fg(GREEN, "self") + dim(fg(GREY, "  continuously re-tolerized to a changing environment")))
        core = fg(GREEN, "(" + "•" * radius + "|" + "•" * radius + ")")
        rows.append("    " + core)
        rows.append("")
        shown = min(len(events), 1 + i // 14)
        for e in range(shown):
            col, s = events[e]
            rows.append(fg(col, s))
        return rows

    scene_frame(sc, head, None, foot, PERI, 84, fps=20, builder=builder)
    for _ in range(24):
        lines = list(head) + [
            "",
            center(bold(fg(PERI, "▰  CALIBRATED, UNATTENDED  ▰")), W),
            "",
            center("41 days live  ·  " + fg(GREEN, "0 false positives") + "  ·  " + fg(VIOLET, "3 autoreactive detectors retired"), W),
            "",
            center(dim(fg(GREY, "churn that rots a static model keeps this one sharp")), W),
        ]
        while len(lines) < sc.height - 2:
            lines.append("")
        lines.append(fg(DGREY, "  " + "─" * (W - 2)))
        lines.append(dim(fg(GREY, "  " + foot)))
        sc.draw(lines, 0.055)


# ======================================================================
# 5 · CYTOKINE STORM — adaptive, local inflammation
# ======================================================================
def scene_cytokine(sc):
    head = header("⑤", "ADAPTIVE INFLAMMATION", "dendritic signaling · sharper exactly where it is probed", YELLOW)
    foot = "danger signals raise local sensitivity · graded · self-limiting · bounded"
    ROWS, COLS = 7, 30
    hot_r, hot_c = 3, 20
    heat = [[0.0] * COLS for _ in range(ROWS)]

    def render_grid(sens):
        out = []
        chars = " ·▪▴◆█"
        for r in range(ROWS):
            line = "   "
            for c in range(COLS):
                h = heat[r][c]
                if h <= 0.02:
                    line += fg(DGREY, "·")
                else:
                    idx = min(len(chars) - 1, 1 + int(h * (len(chars) - 1)))
                    col = GREEN if h < 0.34 else (YELLOW if h < 0.67 else RED)
                    line += fg(col, chars[idx])
            out.append(line)
        return out

    # phase A: probing + heating
    for i in range(50):
        # attacker probes near hot spot
        for _ in range(2):
            rr = max(0, min(ROWS - 1, hot_r + random.randint(-1, 1)))
            cc = max(0, min(COLS - 1, hot_c + random.randint(-2, 2)))
            heat[rr][cc] = min(1.0, heat[rr][cc] + 0.28)
        # diffuse slightly
        if i % 3 == 0:
            for r in range(ROWS):
                for c in range(COLS):
                    heat[r][c] = max(0.0, heat[r][c] - 0.02)
        sens = min(1.0, sum(sum(row) for row in heat) / 14.0)
        caught = i > 26
        rows = ["  " + fg(RED, "probe campaign") + dim(fg(GREY, "  an attacker iterates variants to find a gap")), ""]
        rows += render_grid(sens)
        rows += [""]
        rows.append("    local sensitivity  " + bar(sens, 26, YELLOW if sens < 0.7 else RED) + bold(fg(WHITE, f"  +{int(sens*52)}%")))
        if caught:
            rows.append("    " + fg(GREEN, "✓ the probed neighborhood is now too hot to pass"))
        else:
            rows.append("    " + dim(fg(GREY, "cytokines recruiting scrutiny toward the pressure …")))
        lines = list(head) + rows
        while len(lines) < sc.height - 2:
            lines.append("")
        lines.append(fg(DGREY, "  " + "─" * (W - 2)))
        lines.append(dim(fg(GREY, "  " + foot)))
        sc.draw(lines, 0.06)
    # phase B: resolve
    for i in range(30):
        for r in range(ROWS):
            for c in range(COLS):
                heat[r][c] = max(0.0, heat[r][c] - 0.05)
        sens = max(0.0, min(1.0, sum(sum(row) for row in heat) / 14.0))
        rows = ["  " + fg(GREEN, "pressure resolved") + dim(fg(GREY, "  inflammation recedes to baseline — bounded by design")), ""]
        rows += render_grid(sens)
        rows += [""]
        rows.append("    local sensitivity  " + bar(sens, 26, GREEN) + bold(fg(WHITE, "  → baseline")))
        rows.append("    " + dim(fg(GREY, "damped & rate-limited: no self-inflicted false-positive storm")))
        lines = list(head) + rows
        while len(lines) < sc.height - 2:
            lines.append("")
        lines.append(fg(DGREY, "  " + "─" * (W - 2)))
        lines.append(dim(fg(GREY, "  " + foot)))
        sc.draw(lines, 0.06)
    for _ in range(22):
        lines = list(head) + [
            "",
            center(bold(fg(YELLOW, "▰  PROBE CAMPAIGN ABSORBED  ▰")), W),
            "",
            center("the attacker's own reconnaissance " + fg(WHITE, "sharpened the defense"), W),
            "",
            center(dim(fg(GREY, "the more they probe a region, the harder it becomes to pass")), W),
        ]
        while len(lines) < sc.height - 2:
            lines.append("")
        lines.append(fg(DGREY, "  " + "─" * (W - 2)))
        lines.append(dim(fg(GREY, "  " + foot)))
        sc.draw(lines, 0.055)


# ======================================================================
# CLOSE
# ======================================================================
def scene_close(sc):
    props = [
        (VIOLET, "①", "germinal center", "self-play, overnight"),
        (CYAN, "②", "vaccine forecaster", "immune before the strain"),
        (GREEN, "③", "herd immunity", "the fleet, as one"),
        (PERI, "④", "living self", "never frozen"),
        (YELLOW, "⑤", "adaptive inflammation", "sharper under fire"),
    ]
    for step in range(len(props) + 30):
        lines = ["", ""]
        for r, row in enumerate(LOGO):
            lines.append(center(fg(GRAD[r], row), W))
        lines.append("")
        lines.append(center(bold(fg(PERI, "THE ADAPTIVE IMMUNE SYSTEM")), W))
        lines.append("")
        for p in range(min(step, len(props))):
            col, num, name, tag = props[p]
            s = fg(col, f"{num} ") + bold(fg(WHITE, f"{name:<22}")) + dim(fg(GREY, tag))
            lines.append(center(s, W))
        if step >= len(props):
            lines.append("")
            lines.append(center(dim(fg(VIOLET, "▞  a vision of the autonomous immune system  ▞")), W))
            lines.append(center(dim(fg(GREY, "offline · air-gapped · deterministic · self-evolving")), W))
        while len(lines) < sc.height:
            lines.append("")
        sc.draw(lines, 0.11 if step < len(props) else 0.05)


SCENES = {
    "title": scene_title,
    "germinal": scene_germinal,
    "forecaster": scene_forecaster,
    "herd": scene_herd,
    "living": scene_living,
    "cytokine": scene_cytokine,
    "close": scene_close,
}
ORDER = ["title", "germinal", "forecaster", "herd", "living", "cytokine", "close"]


def main():
    sc = Screen(height=22)
    try:
        if len(sys.argv) > 1 and sys.argv[1] in SCENES:
            SCENES[sys.argv[1]](sc)
        else:
            for name in ORDER:
                SCENES[name](sc)
        # long final hold so the recorder can stop on the close frame
        time.sleep(12)
    finally:
        sc.close()


if __name__ == "__main__":
    main()

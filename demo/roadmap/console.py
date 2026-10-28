#!/usr/bin/env python3
"""
agat — CAPABILITY CONSOLE (roadmap preview).

An interactive TUI *prototype* of agat's future capability console: the five
roadmap immune capabilities as selectable actions you drive from the keyboard.
It reads real keystrokes (↑/↓/j/k to select, ⏎ to run, q to quit), so a
recorder like VHS drives it exactly as a person would.

This is a PROTOTYPE of features that do not ship yet — the header and footer
say "roadmap preview / not yet shipped", and the real `agat` binary has none
of these actions. Record with demo/roadmap/console.tape.
"""
import sys
import time
import termios
import tty

# ---- palette ---------------------------------------------------------
CYAN = (94, 242, 255)
PERI = (143, 168, 255)
VIOLET = (208, 123, 255)
GREEN = (46, 204, 113)
YELLOW = (255, 200, 87)
RED = (255, 92, 122)
GREY = (120, 134, 166)
DGREY = (70, 80, 104)
WHITE = (226, 236, 255)
BLACK = (16, 16, 24)

HEIGHT = 22
LW = 30   # left pane inner width
RW = 42   # right pane inner width


def fg(rgb, s):
    r, g, b = rgb
    return f"\x1b[38;2;{r};{g};{b}m{s}\x1b[0m"


def bold(s):
    return f"\x1b[1m{s}\x1b[0m"


def dim(s):
    return f"\x1b[2m{s}\x1b[0m"


def chip(s, rgb):
    r, g, b = rgb
    return f"\x1b[1;48;2;{r};{g};{b}m\x1b[38;2;16;16;24m {s} \x1b[0m"


def vlen(s):
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


def fit(s, w):
    """Pad/truncate a (possibly colored) string to visible width w."""
    pad = w - vlen(s)
    if pad >= 0:
        return s + " " * pad
    return s  # assume caller sized it


def bar(frac, width, color):
    frac = max(0.0, min(1.0, frac))
    n = int(round(frac * width))
    return fg(color, "█" * n) + fg(DGREY, "░" * (width - n))


# ---- capabilities ----------------------------------------------------
CAPS = [
    {
        "name": "Germinal center",
        "tag": "self-play maturation",
        "accent": VIOLET,
        "biology": "somatic hypermutation",
        "desc": [
            "Generate adversarial variants of known",
            "families, throw them at the repertoire,",
            "promote the ones that evade, hypermutate,",
            "and re-select — overnight, unattended.",
        ],
        "steps": [
            ("spawning adversarial variants", 0.40),
            ("hypermutating repertoire", 0.72),
            ("negative-selecting survivors", 0.90),
            ("cloning high-affinity detectors", 0.994),
        ],
        "result": [
            ("coverage", "61.0% → 99.4%", GREEN),
            ("new memory cells", "+12", WHITE),
            ("variants absorbed", "1,284,301", WHITE),
        ],
        "accepted": "self-play round accepted · repertoire hardened",
    },
    {
        "name": "Vaccine forecaster",
        "tag": "pre-immunize",
        "accent": CYAN,
        "biology": "strain forecasting",
        "desc": [
            "Project a family's mutation space forward",
            "and pre-build memory cells for variants",
            "that have not been written yet — immune",
            "before the first real encounter.",
        ],
        "steps": [
            ("projecting mutation space", 0.35),
            ("synthesizing attenuated antigens", 0.66),
            ("pre-building memory cells", 1.0),
        ],
        "result": [
            ("future strains immunized", "2,847", GREEN),
            ("forecast horizon", "+6 months", WHITE),
            ("first-contact latency", "0 ms", WHITE),
        ],
        "accepted": "forecast accepted · pre-immunization staged",
    },
    {
        "name": "Herd immunity",
        "tag": "fleet antibodies",
        "accent": GREEN,
        "biology": "population memory",
        "desc": [
            "One node matures a response and signs an",
            "antibody pack; it propagates to the fleet.",
            "No samples, no telemetry — learned immunity",
            "crosses the air gap, not evidence.",
        ],
        "steps": [
            ("maturing response", 0.30),
            ("signing antibody pack", 0.55),
            ("propagating across fleet", 1.0),
        ],
        "result": [
            ("nodes immunized", "1,204", GREEN),
            ("sample data moved", "0 bytes", WHITE),
            ("sync time", "0.3 s", WHITE),
        ],
        "accepted": "antibody pack accepted · fleet immunized",
    },
    {
        "name": "Living self",
        "tag": "continuous tolerance",
        "accent": PERI,
        "biology": "re-tolerization + Tregs",
        "desc": [
            "Fold benign drift into self continuously,",
            "and let a regulatory layer retire detectors",
            "that start firing on your own software —",
            "self-restraint against false positives.",
        ],
        "steps": [
            ("folding benign drift into self", 0.45),
            ("re-running negative selection", 0.75),
            ("regulating autoreactive detectors", 1.0),
        ],
        "result": [
            ("self re-tolerized", "3 new builds", GREEN),
            ("autoreactive detectors retired", "3", VIOLET),
            ("false positives", "0", WHITE),
        ],
        "accepted": "re-tolerization accepted · self recalibrated",
    },
    {
        "name": "Adaptive inflammation",
        "tag": "danger signaling",
        "accent": YELLOW,
        "biology": "dendritic cytokines",
        "desc": [
            "When one analyzer sees danger it signals",
            "the others, raising sensitivity right where",
            "a campaign is probing — graded, local, and",
            "self-limiting back to baseline.",
        ],
        "steps": [
            ("sensing probe campaign", 0.50),
            ("raising local sensitivity", 0.95),
            ("resolving to baseline", 0.15),
        ],
        "result": [
            ("local sensitivity", "+52%", YELLOW),
            ("neighborhood", "hardened", GREEN),
            ("storm bound", "self-limited", WHITE),
        ],
        "accepted": "inflammation accepted · bounded & resolved",
    },
]


class Term:
    def __init__(self):
        self.fd = sys.stdin.fileno()
        self.old = termios.tcgetattr(self.fd)
        tty.setraw(self.fd)
        sys.stdout.write("\x1b[?25l\x1b[2J")
        sys.stdout.flush()

    def getch(self, timeout=None):
        import select
        r, _, _ = select.select([sys.stdin], [], [], timeout)
        if not r:
            return None
        ch = sys.stdin.read(1)
        if ch == "\x1b":
            # arrow sequence
            r2, _, _ = select.select([sys.stdin], [], [], 0.01)
            if r2:
                seq = sys.stdin.read(2)
                return {"[A": "k", "[B": "j"}.get(seq, "")
        return ch

    def close(self):
        sys.stdout.write("\x1b[?25h\x1b[0m\x1b[2J\x1b[H")
        sys.stdout.flush()
        termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old)


def compose(cursor, right_lines, status=None, status_color=GREEN):
    """Build the whole TUI as a list of screen lines."""
    lines = []
    # header
    head = " " + chip("agat", CYAN) + "  " + fg(GREY, "capability console")
    badge = fg(VIOLET, "◇ roadmap preview")
    gap = max(1, (LW + RW + 6) - vlen(head) - vlen(badge))
    lines.append(head + " " * gap + badge)
    lines.append("")
    # box tops
    lt = fg(DGREY, "┌─ ") + bold(fg(PERI, "capabilities")) + fg(DGREY, " " + "─" * (LW - 15) + "┐")
    cap = CAPS[cursor]
    rtitle = bold(fg(cap["accent"], cap["name"]))
    rt = fg(DGREY, "┌─ ") + rtitle + fg(DGREY, " " + "─" * max(1, RW - 3 - len(cap["name"])) + "┐")
    lines.append("  " + lt + " " + rt)
    # body rows
    right = list(right_lines)
    for i in range(HEIGHT - 7):
        # left cell
        if i < len(CAPS):
            c = CAPS[i]
            sel = i == cursor
            if sel:
                inner = " ▸ " + bold(c["name"])
                cell = f"\x1b[48;2;30;36;56m" + fit(fg(c["accent"], " ▸ ") + bold(fg(WHITE, c["name"])), LW) + "\x1b[0m"
            else:
                cell = fit("   " + fg(GREY, c["name"]), LW)
            # second line: tag under name
            left_cell = cell
        elif i == len(CAPS) + 1:
            left_cell = fit("   " + dim(fg(GREY, "five capabilities")), LW)
        else:
            left_cell = " " * LW
        # right cell
        rcell = fit(right[i], RW) if i < len(right) else " " * RW
        lines.append("  " + fg(DGREY, "│") + left_cell + fg(DGREY, "│") + " " + fg(DGREY, "│") + rcell + fg(DGREY, "│"))
    # box bottoms
    lb = fg(DGREY, "└" + "─" * LW + "┘")
    rb = fg(DGREY, "└" + "─" * RW + "┘")
    lines.append("  " + lb + " " + rb)
    # status / footer
    if status:
        lines.append(" " + chip("✓", status_color) + " " + fg(status_color, status))
    else:
        keys = (dim(fg(GREY, "  ")) + chip("↑/↓", GREY) + fg(GREY, " select   ")
                + chip("⏎", GREY) + fg(GREY, " run   ")
                + chip("q", GREY) + fg(GREY, " quit"))
        lines.append(keys)
    lines.append(" " + dim(fg(GREY, "◇ roadmap preview · these actions do not ship yet · prototype")))
    return lines


def draw(lines):
    buf = ["\x1b[H"]
    for i in range(HEIGHT):
        s = lines[i] if i < len(lines) else ""
        buf.append(s + "\x1b[K")
        if i < HEIGHT - 1:
            buf.append("\r\n")
    sys.stdout.write("".join(buf))
    sys.stdout.flush()


def idle_right(cap):
    out = []
    out.append(" " + dim(fg(GREY, cap["biology"])))
    out.append("")
    for d in cap["desc"]:
        out.append(" " + fg(WHITE, d))
    out.append("")
    out.append(" " + chip("⏎", cap["accent"]) + fg(GREY, "  run this capability"))
    return out


def run_right(cap, frac_overall, step_states):
    out = []
    out.append(" " + dim(fg(GREY, cap["biology"])))
    out.append("")
    out.append(" " + bold(fg(cap["accent"], "running…")))
    out.append("")
    for (label, _), state in zip(cap["steps"], step_states):
        if state == 2:
            out.append("  " + fg(GREEN, "✓ ") + fg(GREY, label))
        elif state == 1:
            out.append("  " + fg(YELLOW, "◆ ") + fg(WHITE, label))
        else:
            out.append("  " + fg(DGREY, "· ") + dim(fg(GREY, label)))
    out.append("")
    out.append("  progress  " + bar(frac_overall, 24, cap["accent"]))
    return out


def result_right(cap):
    out = []
    out.append(" " + dim(fg(GREY, cap["biology"])))
    out.append("")
    out.append(" " + bold(fg(GREEN, "✓ accepted")))
    out.append("")
    for label, val, col in cap["result"]:
        out.append("  " + fg(GREY, fit(label, 26)) + bold(fg(col, val)))
    out.append("")
    out.append(" " + dim(fg(GREY, "returns to the console — select another")))
    return out


def run_capability(term, cursor):
    cap = CAPS[cursor]
    nsteps = len(cap["steps"])
    frames = 42
    for f in range(frames + 1):
        t = f / frames
        # which steps are done / active
        states = []
        cur = int(t * nsteps)
        for s in range(nsteps):
            if s < cur:
                states.append(2)
            elif s == cur:
                states.append(1)
            else:
                states.append(0)
        # overall progress tracks the last step's target
        target = cap["steps"][min(nsteps - 1, cur)][1]
        prev = cap["steps"][cur - 1][1] if cur > 0 else 0.3
        local = (t * nsteps) - cur
        frac = prev + (target - prev) * min(1.0, local * 1.3)
        draw(compose(cursor, run_right(cap, frac, states),
                     status=f"running {cap['name'].lower()} …", status_color=cap["accent"]))
        time.sleep(0.06)
    # settle: all steps done
    draw(compose(cursor, run_right(cap, cap["steps"][-1][1], [2] * nsteps),
                 status=f"running {cap['name'].lower()} …", status_color=cap["accent"]))
    time.sleep(0.25)
    # result
    draw(compose(cursor, result_right(cap), status=cap["accepted"], status_color=GREEN))


def main():
    term = Term()
    cursor = 0
    done = set()
    try:
        draw(compose(cursor, idle_right(CAPS[cursor])))
        while True:
            ch = term.getch(timeout=30)
            if ch is None or ch == "q" or ch == "\x03":
                break
            if ch in ("j",):
                cursor = (cursor + 1) % len(CAPS)
                draw(compose(cursor, idle_right(CAPS[cursor])))
            elif ch in ("k",):
                cursor = (cursor - 1) % len(CAPS)
                draw(compose(cursor, idle_right(CAPS[cursor])))
            elif ch in ("\r", "\n"):
                run_capability(term, cursor)
                done.add(cursor)
    finally:
        term.close()


if __name__ == "__main__":
    main()

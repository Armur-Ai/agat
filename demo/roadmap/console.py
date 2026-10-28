#!/usr/bin/env python3
"""
agat — CAPABILITY CONSOLE (prototype).

An interactive TUI prototype of agat's capability console: immune capabilities
as selectable actions you drive from the keyboard (↑/↓/j/k select, ⏎ run,
q quit). It reads real keystrokes, so a recorder like VHS drives it exactly as
a person would. Each action runs with a live, capability-specific widget and is
accepted with a result panel.

These capabilities are in development — the footer says so, and the shipping
`agat` binary has none of these actions. Record with demo/roadmap/console.tape.
"""
import sys
import time
import math
import random
import termios
import tty

random.seed(11)

CYAN = (94, 242, 255)
PERI = (143, 168, 255)
VIOLET = (208, 123, 255)
GREEN = (46, 204, 113)
YELLOW = (255, 200, 87)
RED = (255, 92, 122)
GREY = (120, 134, 166)
DGREY = (66, 76, 100)
WHITE = (226, 236, 255)

HEIGHT = 23
LW = 30
RW = 44


def fg(rgb, s):
    r, g, b = rgb
    return f"\x1b[38;2;{r};{g};{b}m{s}\x1b[0m"


def bg(rgb, s):
    r, g, b = rgb
    return f"\x1b[48;2;{r};{g};{b}m{s}\x1b[0m"


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
    pad = w - vlen(s)
    return s + " " * pad if pad > 0 else s


def bar(frac, width, color):
    frac = max(0.0, min(1.0, frac))
    n = int(round(frac * width))
    return fg(color, "▰" * n) + fg(DGREY, "▱" * (width - n))


def hexid(n=10):
    return "".join(random.choice("0123456789abcdef") for _ in range(n))


# ---- capability-specific live run widgets ----------------------------
def w_germinal(t):
    rows = []
    for _ in range(2):
        evade = random.random() < 0.16 and t < 0.95
        mark = fg(RED, "✗") if evade else fg(GREEN, "✓")
        kind = random.choice(["poly", "meta", "ai-rw", "poly+meta"])
        rows.append("  " + mark + " " + fg(DGREY, hexid(10)) + dim(fg(GREY, "  " + kind)))
    g = min(5, int(t * 5) + 1)
    rows.append("  " + fg(VIOLET, f"generation {g}/5") + dim(fg(GREY, "  mutate→select→clone")))
    return rows


def w_forecaster(t):
    span = 20
    filled = int(min(1.0, t) * span)
    head = fg(CYAN, "├") + fg(VIOLET, "━" * filled)
    if filled < span:
        head += fg(CYAN, "◆") + fg(DGREY, "┄" * (span - filled - 1))
    head += fg(CYAN, "→")
    rows = ["  " + dim(fg(GREY, "today ")) + head + dim(fg(GREY, " +6mo"))]
    rows.append("  " + dim(fg(GREY, "synthesizing antigens along each branch")))
    rows.append("")
    return rows


def w_herd(t):
    N = 26
    lit = int(min(1.0, t) * N)
    row = "".join((fg(GREEN, "●") if i < lit else fg(DGREY, "·")) for i in range(N))
    rows = ["  " + row]
    rows.append("  " + dim(fg(GREY, "antibody pack propagating · 0 samples moved")))
    rows.append("")
    return rows


def w_living(t):
    r = int(7 + (math.sin(t * 6.0) * 0.5 + 0.5) * 5)
    rows = ["  " + fg(GREEN, "self (") + fg(GREEN, "•" * r) + fg(WHITE, "|") + fg(GREEN, "•" * r) + fg(GREEN, ")")]
    rows.append("  " + dim(fg(GREY, "folding drift · regulating detectors")))
    rows.append("")
    return rows


def w_cytokine(t):
    N = 26
    row = ""
    for i in range(N):
        d = abs(i - 17)
        hot = d < 8 and random.random() < min(1.0, t * 1.1) * (1 - d / 10)
        if hot:
            col = RED if d < 3 else (YELLOW if d < 6 else GREEN)
            row += fg(col, "▆")
        else:
            row += fg(DGREY, "·")
    rows = ["  " + row]
    rows.append("  " + dim(fg(GREY, "sensitivity rising where it's probed")))
    rows.append("")
    return rows


CAPS = [
    {
        "name": "Germinal center", "tag": "self-play maturation", "accent": VIOLET,
        "biology": "somatic hypermutation",
        "desc": ["Generate adversarial variants, throw them",
                 "at the repertoire, promote the ones that",
                 "evade, hypermutate and re-select —",
                 "overnight, unattended."],
        "steps": [("spawning adversarial variants", 0.40), ("hypermutating repertoire", 0.72),
                  ("negative-selecting survivors", 0.90), ("cloning high-affinity detectors", 0.994)],
        "widget": w_germinal, "live": ("variants absorbed", 1284301, "", WHITE),
        "result": [("coverage", "61.0% → 99.4%", GREEN), ("new memory cells", "+12", WHITE),
                   ("variants absorbed", "1,284,301", WHITE)],
        "accepted": "self-play round accepted · repertoire hardened",
    },
    {
        "name": "Vaccine forecaster", "tag": "pre-immunize", "accent": CYAN,
        "biology": "strain forecasting",
        "desc": ["Project a family's mutation space forward",
                 "and pre-build memory cells for variants",
                 "that have not been written yet — immune",
                 "before the first encounter."],
        "steps": [("projecting mutation space", 0.35), ("synthesizing attenuated antigens", 0.66),
                  ("pre-building memory cells", 1.0)],
        "widget": w_forecaster, "live": ("strains immunized", 2847, "", GREEN),
        "result": [("future strains immunized", "2,847", GREEN), ("forecast horizon", "+6 months", WHITE),
                   ("first-contact latency", "0 ms", WHITE)],
        "accepted": "forecast accepted · pre-immunization staged",
    },
    {
        "name": "Herd immunity", "tag": "fleet antibodies", "accent": GREEN,
        "biology": "population memory",
        "desc": ["One node matures a response and signs an",
                 "antibody pack; it propagates to the fleet.",
                 "No samples, no telemetry — learned",
                 "immunity crosses the air gap."],
        "steps": [("maturing response", 0.30), ("signing antibody pack", 0.55),
                  ("propagating across fleet", 1.0)],
        "widget": w_herd, "live": ("nodes immunized", 1204, "", GREEN),
        "result": [("nodes immunized", "1,204", GREEN), ("sample data moved", "0 bytes", WHITE),
                   ("sync time", "0.3 s", WHITE)],
        "accepted": "antibody pack accepted · fleet immunized",
    },
    {
        "name": "Living self", "tag": "continuous tolerance", "accent": PERI,
        "biology": "re-tolerization + Tregs",
        "desc": ["Fold benign drift into self continuously,",
                 "and let a regulatory layer retire detectors",
                 "that fire on your own software —",
                 "self-restraint against false positives."],
        "steps": [("folding benign drift into self", 0.45), ("re-running negative selection", 0.75),
                  ("regulating autoreactive detectors", 1.0)],
        "widget": w_living, "live": ("detectors retired", 3, "", VIOLET),
        "result": [("self re-tolerized", "3 new builds", GREEN), ("autoreactive detectors retired", "3", VIOLET),
                   ("false positives", "0", WHITE)],
        "accepted": "re-tolerization accepted · self recalibrated",
    },
    {
        "name": "Adaptive inflammation", "tag": "danger signaling", "accent": YELLOW,
        "biology": "dendritic cytokines",
        "desc": ["When one analyzer sees danger it signals",
                 "the others, raising sensitivity right where",
                 "a campaign is probing — graded, local,",
                 "and self-limiting back to baseline."],
        "steps": [("sensing probe campaign", 0.50), ("raising local sensitivity", 0.95),
                  ("resolving to baseline", 1.0)],
        "widget": w_cytokine, "live": ("local sensitivity", 52, "%", YELLOW),
        "result": [("local sensitivity", "+52%", YELLOW), ("neighborhood", "hardened", GREEN),
                   ("storm bound", "self-limited", WHITE)],
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
            r2, _, _ = select.select([sys.stdin], [], [], 0.01)
            if r2:
                seq = sys.stdin.read(2)
                return {"[A": "k", "[B": "j"}.get(seq, "")
        return ch

    def close(self):
        sys.stdout.write("\x1b[?25h\x1b[0m\x1b[2J\x1b[H")
        sys.stdout.flush()
        termios.tcsetattr(self.fd, termios.TCSADRAIN, self.old)


def rbox_top(title, w, accent):
    t = fg(DGREY, "╭─ ") + bold(fg(accent, title))
    rest = w - 3 - len(title) - 1
    return t + fg(DGREY, " " + "─" * max(1, rest) + "╮")


def rbox_bot(w):
    return fg(DGREY, "╰" + "─" * (w) + "╯")


def compose(cursor, right_lines, done, status=None, status_color=GREEN, pulse=0):
    lines = []
    dotcol = GREEN if (pulse // 6) % 2 == 0 else (30, 120, 70)
    head = (" " + chip("agat", CYAN) + "  " + fg(GREY, "capability console"))
    rightind = fg(dotcol, "●") + fg(GREY, " immune · online")
    gap = max(1, (LW + RW + 5) - vlen(head) - vlen(rightind))
    lines.append(head + " " * gap + rightind)
    lines.append("")
    cap = CAPS[cursor]
    lines.append("  " + rbox_top("capabilities", LW, PERI) + " " + rbox_top(cap["name"], RW, cap["accent"]))
    right = list(right_lines)
    body = HEIGHT - 7
    for i in range(body):
        # left cell
        if i < len(CAPS):
            c = CAPS[i]
            is_sel = i == cursor
            is_done = i in done
            dot = (fg(GREEN, "✓") if is_done else (fg(c["accent"], "●") if is_sel else fg(DGREY, "○")))
            if is_sel:
                cell = bg((28, 34, 54), fit(" " + dot + " " + bold(fg(WHITE, c["name"])), LW))
            else:
                nm = fg(GREY, c["name"]) if not is_done else fg((150, 200, 170), c["name"])
                cell = fit(" " + dot + " " + nm, LW)
            left_cell = cell
        elif i == cursor + 1 or (cursor == len(CAPS) - 1 and i == len(CAPS)):
            # tag under the selected capability (or just below the list)
            left_cell = fit("     " + dim(fg(CAPS[cursor]["accent"], "· " + CAPS[cursor]["tag"])), LW)
        else:
            left_cell = " " * LW
        rcell = fit(right[i], RW) if i < len(right) else " " * RW
        lines.append("  " + fg(DGREY, "│") + left_cell + fg(DGREY, "│") + " " + fg(DGREY, "│") + rcell + fg(DGREY, "│"))
    lines.append("  " + rbox_bot(LW) + " " + rbox_bot(RW))
    # footer
    if status:
        lines.append(" " + chip("✓", status_color) + " " + fg(status_color, status))
    else:
        keys = ("  " + chip("↑/↓", GREY) + fg(GREY, " select   ") + chip("⏎", GREY)
                + fg(GREY, " run   ") + chip("q", GREY) + fg(GREY, " quit"))
        tail = dim(fg(GREY, "◇ in development"))
        gap2 = max(1, (LW + RW + 5) - vlen(keys) - vlen(tail))
        lines.append(keys + " " * gap2 + tail)
    lines.append(" " + dim(fg(GREY, "the immune system, extended · capability prototype")))
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
    out = [" " + dim(fg(GREY, cap["biology"])), ""]
    for d in cap["desc"]:
        out.append(" " + fg(WHITE, d))
    out.append("")
    out.append(" " + chip("⏎", cap["accent"]) + fg(GREY, "  run this capability"))
    return out


def run_right(cap, t, step_states, live_val):
    out = [" " + dim(fg(GREY, cap["biology"])), ""]
    for (label, _), st in zip(cap["steps"], step_states):
        if st == 2:
            out.append("  " + fg(GREEN, "✓ ") + fg(GREY, label))
        elif st == 1:
            out.append("  " + fg(YELLOW, "◆ ") + fg(WHITE, label))
        else:
            out.append("  " + fg(DGREY, "· ") + dim(fg(GREY, label)))
    out.append("")
    out += cap["widget"](t)
    out.append(" progress  " + bar(t, 22, cap["accent"]) + bold(fg(WHITE, f"  {int(t*100):3d}%")))
    lbl, _, suf, col = cap["live"]
    out.append(" " + fg(GREY, fit(lbl, 22)) + bold(fg(col, f"{live_val:,}{suf}")))
    return out


def result_right(cap):
    out = [" " + dim(fg(GREY, cap["biology"])), "", " " + bold(fg(GREEN, "✓ accepted")), ""]
    for label, val, col in cap["result"]:
        out.append("  " + fg(GREY, fit(label, 28)) + bold(fg(col, val)))
    out.append("")
    out.append(" " + dim(fg(GREY, "returns to the console — select another")))
    return out


def run_capability(cursor, done):
    cap = CAPS[cursor]
    nsteps = len(cap["steps"])
    frames = 46
    tgt = cap["live"][1]
    for f in range(frames + 1):
        t = f / frames
        cur = min(nsteps - 1, int(t * nsteps))
        states = [2 if s < cur else (1 if s == cur else 0) for s in range(nsteps)]
        live_val = int(tgt * (t ** 0.7))
        draw(compose(cursor, run_right(cap, t, states, live_val), done,
                     status=f"running {cap['name'].lower()} …", status_color=cap["accent"], pulse=f))
        time.sleep(0.055)
    draw(compose(cursor, run_right(cap, 1.0, [2] * nsteps, tgt), done,
                 status=f"running {cap['name'].lower()} …", status_color=cap["accent"]))
    time.sleep(0.2)
    done.add(cursor)
    draw(compose(cursor, result_right(cap), done, status=cap["accepted"], status_color=GREEN))


def intro():
    """A short title/transition screen before the console list."""
    logo = ["╭─╮ ╭─╮ ╭─╮ ╭┬╮", "│ │ │ ╶ │ │  │ ", "╵ ╵ ╰─╯ ╵ ╵  ╵ "]
    title = "CAPABILITY CONSOLE"
    for k in range(len(title) + 1):
        lines = ["", "", "", ""]
        lines.append("           " + fg(CYAN, "agat"))
        lines.append("")
        lines.append("      " + bold(fg(PERI, title[:k])))
        lines.append("")
        lines.append("      " + dim(fg(GREY, "the immune system, extended →")))
        while len(lines) < HEIGHT:
            lines.append("")
        draw(lines)
        time.sleep(0.045)
    time.sleep(1.4)


def main():
    term = Term()
    cursor = 0
    done = set()
    try:
        intro()
        draw(compose(cursor, idle_right(CAPS[cursor]), done))
        while True:
            ch = term.getch(timeout=40)
            if ch is None or ch in ("q", "\x03"):
                break
            if ch == "j":
                cursor = (cursor + 1) % len(CAPS)
                draw(compose(cursor, idle_right(CAPS[cursor]), done))
            elif ch == "k":
                cursor = (cursor - 1) % len(CAPS)
                draw(compose(cursor, idle_right(CAPS[cursor]), done))
            elif ch in ("\r", "\n"):
                run_capability(cursor, done)
    finally:
        term.close()


if __name__ == "__main__":
    main()

//! agat's visual identity: the ASCII logo, a small color palette, and the
//! splash shown when `agat` is run with no command.
//!
//! Colors follow the no-color.org convention — everything degrades to
//! plain text when stdout is not a terminal or `NO_COLOR` is set.

use std::io::IsTerminal;

/// ANSI 24-bit foreground escape, or empty when color is off.
fn fg(r: u8, g: u8, b: u8, color: bool) -> String {
    if color {
        format!("\x1b[38;2;{r};{g};{b}m")
    } else {
        String::new()
    }
}

fn reset(color: bool) -> &'static str {
    if color {
        "\x1b[0m"
    } else {
        ""
    }
}

fn bold(color: bool) -> &'static str {
    if color {
        "\x1b[1m"
    } else {
        ""
    }
}

fn dim(color: bool) -> &'static str {
    if color {
        "\x1b[2m"
    } else {
        ""
    }
}

/// Whether to emit color: stdout is a terminal and `NO_COLOR` is unset.
pub fn use_color() -> bool {
    std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
}

// agat's brand gradient — cyan → periwinkle → violet, matching the README
// banner. One stop per logo row.
const GRADIENT: [(u8, u8, u8); 6] = [
    (94, 242, 255), // cyan
    (122, 190, 255),
    (143, 168, 255), // periwinkle
    (170, 150, 255),
    (197, 130, 255),
    (208, 123, 255), // violet
];

const LOGO: [&str; 6] = [
    r"  █████╗  ██████╗  █████╗ ████████╗",
    r" ██╔══██╗██╔════╝ ██╔══██╗╚══██╔══╝",
    r" ███████║██║  ███╗███████║   ██║   ",
    r" ██╔══██║██║   ██║██╔══██║   ██║   ",
    r" ██║  ██║╚██████╔╝██║  ██║   ██║   ",
    r" ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ",
];

/// The ASCII logo, gradient-colored row by row.
pub fn logo(color: bool) -> String {
    let mut out = String::new();
    for (row, (r, g, b)) in LOGO.iter().zip(GRADIENT) {
        out.push_str(&fg(r, g, b, color));
        out.push_str(row);
        out.push_str(reset(color));
        out.push('\n');
    }
    out
}

/// The full splash: logo, tagline, version, and the quick-start.
pub fn splash(color: bool) -> String {
    let (cr, cg, cb) = GRADIENT[0];
    let (vr, vg, vb) = GRADIENT[5];
    let mut out = String::new();
    out.push('\n');
    out.push_str(&logo(color));
    out.push_str(&format!(
        "   {}{}an adaptive immune system for binaries{}   {}v{}{}\n",
        bold(color),
        fg(143, 168, 255, color),
        reset(color),
        dim(color),
        env!("CARGO_PKG_VERSION"),
        reset(color),
    ));
    out.push_str(&format!(
        "   {}catches polymorphic · metamorphic · AI-rewritten variants, offline{}\n\n",
        dim(color),
        reset(color),
    ));
    let head = |t: &str| {
        format!(
            "   {}{}{}{}\n",
            bold(color),
            fg(cr, cg, cb, color),
            t,
            reset(color)
        )
    };
    let cmd = |c: &str, d: &str| {
        format!(
            "     {}{:<34}{}{}{}{}\n",
            fg(vr, vg, vb, color),
            c,
            reset(color),
            dim(color),
            d,
            reset(color),
        )
    };
    out.push_str(&head("SCAN"));
    out.push_str(&cmd(
        "agat scan <files|dirs…>",
        "analyze and recognize, stateless",
    ));
    out.push_str(&cmd("agat scan ./dir --output table", "one line per file"));
    out.push_str(&cmd("agat diff <a> <b>", "are two samples related?"));
    out.push('\n');
    out.push_str(&head("TRAIN"));
    out.push_str(&cmd(
        "agat ingest … && agat analyze",
        "build the sample library",
    ));
    out.push_str(&cmd("agat self build <ids…>", "model benign \"self\""));
    out.push_str(&cmd("agat repertoire generate", "negative selection"));
    out.push_str(&cmd("agat mature <id> --family X", "teach a family"));
    out.push('\n');
    out.push_str(&head("MORE"));
    out.push_str(&cmd("agat tui", "interactive verdict console"));
    out.push_str(&cmd("agat serve", "local HTTP API for pipelines"));
    out.push_str(&cmd("agat --help", "every command and flag"));
    out.push('\n');
    out.push_str(&format!(
        "   {}docs: docs/READING_OUTPUT.md · github.com/Armur-Ai/agat{}\n\n",
        dim(color),
        reset(color),
    ));
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_splash_has_no_escape_codes() {
        let s = splash(false);
        assert!(!s.contains('\x1b'), "plain splash must carry no ANSI codes");
        assert!(s.contains("agat scan"));
        assert!(s.contains(env!("CARGO_PKG_VERSION")));
    }

    #[test]
    fn colored_splash_resets_every_sequence() {
        let s = splash(true);
        assert!(s.contains('\x1b'));
        // Every run of color should be closed; a crude balance check.
        assert_eq!(
            s.matches("\x1b[0m").count() > 0,
            s.matches("\x1b[38;2;").count() > 0
        );
    }

    #[test]
    fn logo_has_six_rows() {
        assert_eq!(logo(false).lines().count(), 6);
    }
}

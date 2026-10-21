//! agat's visual identity: the ASCII logo and the splash shown when
//! `agat` runs with no command. Colors come from [`crate::style`].

use crate::style::{palette, Style};

// One gradient stop per logo row, cyan → violet.
const GRADIENT: [(u8, u8, u8); 6] = [
    (94, 242, 255),
    (122, 190, 255),
    (143, 168, 255),
    (170, 150, 255),
    (197, 130, 255),
    (208, 123, 255),
];

const LOGO: [&str; 6] = [
    r"  █████╗  ██████╗  █████╗ ████████╗",
    r" ██╔══██╗██╔════╝ ██╔══██╗╚══██╔══╝",
    r" ███████║██║  ███╗███████║   ██║   ",
    r" ██╔══██║██║   ██║██╔══██║   ██║   ",
    r" ██║  ██║╚██████╔╝██║  ██║   ██║   ",
    r" ╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ",
];

/// Re-export so callers keep using `banner::use_color()`.
pub use crate::style::use_color;

/// The ASCII logo, gradient-colored row by row.
pub fn logo(color: bool) -> String {
    let st = Style::new(color);
    let mut out = String::new();
    for (row, rgb) in LOGO.iter().zip(GRADIENT) {
        out.push_str(&st.fg(rgb, row));
        out.push('\n');
    }
    out
}

/// The full splash: logo, tagline, version, and the grouped quick-start.
pub fn splash(color: bool) -> String {
    let st = Style::new(color);
    let mut out = String::new();
    out.push('\n');
    out.push_str(&logo(color));
    out.push_str(&format!(
        "   {}   {}\n",
        st.bold(&st.fg(
            palette::PERIWINKLE,
            "an adaptive immune system for binaries"
        )),
        st.dim(&format!("v{}", env!("CARGO_PKG_VERSION"))),
    ));
    out.push_str(&format!(
        "   {}\n\n",
        st.dim("catches polymorphic · metamorphic · AI-rewritten variants, offline"),
    ));

    let head = |t: &str| format!("   {}\n", st.bold(&st.fg(palette::CYAN, t)));
    let cmd = |c: &str, d: &str| {
        format!(
            "     {}{}\n",
            st.fg(palette::VIOLET, &format!("{c:<34}")),
            st.dim(d)
        )
    };
    out.push_str(&head("SCAN"));
    out.push_str(&cmd(
        "agat scan <files|dirs…>",
        "analyze and recognize, stateless",
    ));
    out.push_str(&cmd("agat scan ./dir --output table", "one line per file"));
    out.push_str(&cmd("… | agat scan -", "scan a sample from stdin"));
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
        "   {}\n\n",
        st.dim("docs: docs/GUIDE.md · github.com/Armur-Ai/agat"),
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
    fn colored_splash_uses_color() {
        assert!(splash(true).contains('\x1b'));
    }

    #[test]
    fn logo_has_six_rows() {
        assert_eq!(logo(false).lines().count(), 6);
    }
}

//! Terminal styling shared across the CLI: the brand palette, ANSI
//! helpers, and severity colors. All of it is gated on [`use_color`], so
//! output is clean plain text when piped or under `NO_COLOR`.

use agat_core::Severity;
use std::io::IsTerminal;
use std::sync::OnceLock;

/// When to emit color, set once from `--color` (default `Auto`).
#[derive(Clone, Copy, PartialEq, Eq, clap::ValueEnum)]
pub enum ColorChoice {
    /// Color when stdout is a terminal and `NO_COLOR` is unset.
    Auto,
    /// Always color.
    Always,
    /// Never color.
    Never,
}

static CHOICE: OnceLock<ColorChoice> = OnceLock::new();

/// Set the global color choice (call once, early). Later calls are no-ops.
pub fn set_choice(c: ColorChoice) {
    let _ = CHOICE.set(c);
}

/// Emit color per the `--color` choice, defaulting to auto: stdout is a
/// terminal and `NO_COLOR` is unset (https://no-color.org).
pub fn use_color() -> bool {
    match CHOICE.get().copied().unwrap_or(ColorChoice::Auto) {
        ColorChoice::Always => true,
        ColorChoice::Never => false,
        ColorChoice::Auto => {
            std::io::stdout().is_terminal() && std::env::var_os("NO_COLOR").is_none()
        }
    }
}

/// Brand palette (24-bit RGB), the cyan → violet gradient of the logo.
pub mod palette {
    pub const CYAN: (u8, u8, u8) = (94, 242, 255);
    pub const PERIWINKLE: (u8, u8, u8) = (143, 168, 255);
    pub const VIOLET: (u8, u8, u8) = (208, 123, 255);
    pub const GREEN: (u8, u8, u8) = (46, 204, 113);
    pub const YELLOW: (u8, u8, u8) = (255, 200, 87);
    pub const RED: (u8, u8, u8) = (255, 92, 122);
}

/// A styler that knows whether color is on, so call sites don't thread a
/// bool through every helper.
#[derive(Clone, Copy)]
pub struct Style {
    pub color: bool,
}

impl Style {
    pub fn new(color: bool) -> Self {
        Self { color }
    }

    /// Wrap `text` in a 24-bit foreground color.
    pub fn fg(&self, (r, g, b): (u8, u8, u8), text: &str) -> String {
        if self.color {
            format!("\x1b[38;2;{r};{g};{b}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn bold(&self, text: &str) -> String {
        if self.color {
            format!("\x1b[1m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    pub fn dim(&self, text: &str) -> String {
        if self.color {
            format!("\x1b[2m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    /// The color for a severity.
    pub fn severity_rgb(sev: Severity) -> (u8, u8, u8) {
        match sev {
            Severity::Malicious => palette::RED,
            Severity::Suspicious => palette::YELLOW,
            Severity::Review => palette::CYAN,
            Severity::Clean => palette::GREEN,
        }
    }

    /// A colored severity label (uppercased for Malicious, to stand out).
    pub fn severity(&self, sev: Severity) -> String {
        let label = match sev {
            Severity::Malicious => "MALICIOUS",
            other => other.label(),
        };
        self.fg(Self::severity_rgb(sev), label)
    }

    /// A severity rendered as a reverse-video badge, e.g. ` MALICIOUS `.
    pub fn severity_badge(&self, sev: Severity) -> String {
        let label = match sev {
            Severity::Malicious => "MALICIOUS",
            Severity::Suspicious => "SUSPICIOUS",
            Severity::Review => "REVIEW",
            Severity::Clean => "CLEAN",
        };
        if self.color {
            let (r, g, b) = Self::severity_rgb(sev);
            format!("\x1b[1;48;2;{r};{g};{b}m\x1b[38;2;16;16;24m {label} \x1b[0m")
        } else {
            format!("[{label}]")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_style_is_transparent() {
        let s = Style::new(false);
        assert_eq!(s.fg(palette::CYAN, "x"), "x");
        assert_eq!(s.bold("x"), "x");
        assert_eq!(s.severity(Severity::Malicious), "MALICIOUS");
        assert_eq!(s.severity_badge(Severity::Clean), "[CLEAN]");
    }

    #[test]
    fn colored_style_wraps_and_resets() {
        let s = Style::new(true);
        let out = s.fg(palette::VIOLET, "x");
        assert!(out.starts_with("\x1b[38;2;208;123;255m") && out.ends_with("\x1b[0m"));
        assert!(s.severity_badge(Severity::Malicious).contains("MALICIOUS"));
    }
}

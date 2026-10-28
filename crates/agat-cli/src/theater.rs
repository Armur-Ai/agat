//! "Theater" mode: an animated, staged rendering of a single scan for
//! demos and presentations. The verdict and every number shown are the
//! *real* [`ScanResult`] — theater only reveals them progressively (the
//! immune pipeline stage by stage, the affinity and danger meters filling
//! from zero, then the verdict stamping in) so an audience can follow the
//! analysis the engine actually performed. It writes only to stdout and
//! never changes the result, so `--output json/sarif/table` and piped use
//! are entirely unaffected.

use crate::style::{palette, Style};
use agat_core::{ScanResult, Severity};
use std::io::Write;
use std::thread::sleep;
use std::time::Duration;

const SPIN: [&str; 10] = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"];
const BAR_W: usize = 18;

fn ms(d: u64) -> Duration {
    Duration::from_millis(d)
}

fn flush() {
    let _ = std::io::stdout().flush();
}

fn short(s: &Option<String>) -> String {
    s.as_deref()
        .map(|f| f.chars().take(8).collect::<String>())
        .unwrap_or_else(|| "—".into())
}

/// A pipeline stage: spin briefly, then resolve to a green check + fact.
fn stage(st: &Style, label: &str, fact: &str) {
    for i in 0..9 {
        print!(
            "\r\x1b[2K    {} {}",
            st.fg(palette::YELLOW, SPIN[i % SPIN.len()]),
            st.dim(label)
        );
        flush();
        sleep(ms(26));
    }
    println!(
        "\r\x1b[2K    {} {:<16} {}",
        st.fg(palette::GREEN, "✓"),
        label,
        st.dim(fact)
    );
}

/// Fill a meter from 0 to `value`, then print the trailing note.
fn fill_meter(st: &Style, label: &str, value: f64, color: (u8, u8, u8), note: &str) {
    let steps = 18;
    for i in 0..=steps {
        let v = value * (i as f64 / steps as f64);
        let filled = (v * BAR_W as f64).round() as usize;
        let bar = format!(
            "{}{}",
            "█".repeat(filled),
            st.dim(&"░".repeat(BAR_W - filled))
        );
        print!(
            "\r\x1b[2K    {:<9} {:>5.3}  {}",
            label,
            v,
            st.fg(color, &bar)
        );
        flush();
        sleep(ms(22));
    }
    println!("   {}", st.bold(note));
}

/// Stamp the final verdict inside a colored box.
fn stamp(st: &Style, sev: Severity, summary: &str) {
    const INNER: usize = 34;
    let (r, g, b) = Style::severity_rgb(sev);
    let rule = |c: char, n: usize| st.fg((r, g, b), &c.to_string().repeat(n));
    println!();
    // brief suspense before the verdict lands
    for i in 0..9 {
        print!(
            "\r\x1b[2K    {} {}",
            st.fg(palette::YELLOW, SPIN[i % SPIN.len()]),
            st.dim("fusing recognition × danger…")
        );
        flush();
        sleep(ms(65));
    }
    print!("\r\x1b[2K");
    // Center the badge in the box. The badge carries ANSI codes, so pad by
    // the *visible* width (label + the two inset spaces), which is the same
    // with or without color.
    let label_len = match sev {
        Severity::Malicious => 9,
        Severity::Suspicious => 10,
        Severity::Review => 6,
        Severity::Clean => 5,
    };
    let vis = label_len + 2;
    let left = (INNER - vis) / 2;
    let right = INNER - vis - left;
    let badge = st.severity_badge(sev);
    println!("    {}{}{}", rule('┏', 1), rule('━', INNER), rule('┓', 1));
    println!(
        "    {}{}{}{}{}",
        rule('┃', 1),
        " ".repeat(left),
        badge,
        " ".repeat(right),
        rule('┃', 1)
    );
    println!("    {}{}{}", rule('┗', 1), rule('━', INNER), rule('┛', 1));
    println!("    {}", st.bold(summary));
}

/// Play the animated scan for one result.
pub fn play(r: &ScanResult, color: bool) {
    let st = Style::new(color);
    let name = r.sample.name.as_deref().unwrap_or(&r.sample.short);

    println!();
    println!(
        "  {}  {}",
        st.bold(&st.fg(palette::CYAN, "◢◤ agat · immune scan ◥◣")),
        st.fg(palette::PERIWINKLE, name)
    );
    println!("  {}", st.dim(&"─".repeat(52)));

    // --- the behavioral pipeline, stage by stage ---
    println!("  {}", st.bold(&st.fg(palette::PERIWINKLE, "PIPELINE")));
    stage(&st, "parse", &format!("content {}", r.sample.short));
    stage(
        &st,
        "disassemble",
        &format!("{} basic blocks", r.antigen.blocks),
    );
    let poly = match &r.antigen.plaintext_fingerprint {
        Some(_) => format!(
            "payload recovered · {}",
            short(&r.antigen.plaintext_fingerprint)
        ),
        None => "no packed payload".to_string(),
    };
    stage(&st, "polymorphic", &poly);
    stage(
        &st,
        "metamorphic",
        &format!("canonical CFG · WL {}", short(&r.antigen.cfg_fingerprint)),
    );
    let llm = r
        .danger
        .signals
        .iter()
        .filter(|s| s.name.starts_with("llm"))
        .count();
    let ai = if llm > 0 {
        format!("{llm} LLM artifact{}", if llm == 1 { "" } else { "s" })
    } else {
        "no LLM artifacts".to_string()
    };
    stage(&st, "AI signals", &ai);
    stage(
        &st,
        "present antigen",
        &format!(
            "signature dim {} · {} blocks",
            r.antigen.dim, r.antigen.blocks
        ),
    );
    println!();

    // --- recognition axis ---
    println!(
        "  {}  {}",
        st.bold(&st.fg(palette::CYAN, "RECOGNITION")),
        st.dim("is it non-self?")
    );
    let rec_note = if let Some(fam) = &r.recognition.family {
        let mem = if r.recognition.secondary_response {
            " · memory cell (secondary response)"
        } else {
            ""
        };
        format!("family {fam}{mem}")
    } else if r.recognition.recognized {
        "non-self · no known family".to_string()
    } else {
        "within self".to_string()
    };
    fill_meter(
        &st,
        "affinity",
        r.recognition.affinity,
        palette::VIOLET,
        &rec_note,
    );
    println!();

    // --- danger axis ---
    println!(
        "  {}  {}",
        st.bold(&st.fg(palette::CYAN, "DANGER")),
        st.dim("is it harmful?")
    );
    let danger_color = if r.danger.score >= 0.5 {
        palette::RED
    } else if r.danger.score >= 0.33 {
        palette::YELLOW
    } else {
        palette::GREEN
    };
    fill_meter(
        &st,
        "score",
        r.danger.score,
        danger_color,
        &format!("context {}", r.danger.context),
    );
    for s in r.danger.signals.iter().take(5) {
        let class_color = match s.class.as_str() {
            "pamp" => palette::RED,
            "danger" => palette::YELLOW,
            _ => palette::GREEN,
        };
        println!(
            "      {:<6} {:<30} {:>4.2}",
            st.fg(class_color, &s.class),
            s.name,
            s.value
        );
        flush();
        sleep(ms(70));
    }

    // --- the fused verdict ---
    stamp(&st, r.verdict.severity, &r.verdict.summary);
    println!();
}

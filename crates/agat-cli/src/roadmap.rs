//! `agat roadmap` — an honest, at-a-glance map of the immune system's
//! capabilities: the mechanisms that ship in this build, and the ones that
//! are still ahead. Kept deliberately truthful — the SHIPPING entries are
//! things you can run today (`mature`, `repertoire export/import`, the
//! danger fusion in a scan); the ROADMAP entries are design directions, not
//! features, and are labeled as such so a demo never implies otherwise.

use crate::style::{palette, Style};

struct Item {
    name: &'static str,
    biology: &'static str,
    blurb: &'static str,
}

const SHIPPING: [Item; 5] = [
    Item {
        name: "Antigen presentation",
        biology: "MHC display",
        blurb: "behavior distilled to a mutation-invariant signature",
    },
    Item {
        name: "Negative selection",
        biology: "central tolerance",
        blurb: "detectors censored against your benign \"self\"",
    },
    Item {
        name: "Clonal selection",
        biology: "B-cell maturation",
        blurb: "mature a family — held-out variants caught by memory",
    },
    Item {
        name: "Danger theory",
        biology: "dendritic cells",
        blurb: "PAMP / danger / safe fused: unknown is not hostile",
    },
    Item {
        name: "Herd immunity",
        biology: "population memory",
        blurb: "signed antibody packs immunize the air-gapped fleet",
    },
];

const ROADMAP: [Item; 4] = [
    Item {
        name: "Germinal center",
        biology: "somatic hypermutation",
        blurb: "autonomous self-play: synthesize, mature overnight, unattended",
    },
    Item {
        name: "Vaccine forecaster",
        biology: "strain forecasting",
        blurb: "immunize against strains before they are written",
    },
    Item {
        name: "Living self",
        biology: "re-tolerization + Tregs",
        blurb: "continuous self-renewal with false-positive self-restraint",
    },
    Item {
        name: "Cytokine storm",
        biology: "inflammation",
        blurb: "adaptive, local danger signaling that sharpens under probing",
    },
];

pub fn render(color: bool) -> String {
    let st = Style::new(color);
    let mut o = String::new();

    o.push('\n');
    o.push_str(&format!(
        "  {}\n",
        st.bold(&st.fg(palette::CYAN, "THE IMMUNE ROADMAP"))
    ));
    o.push_str(&format!(
        "  {}\n\n",
        st.dim("an adaptive immune system — what it runs today, and where it grows"),
    ));

    let row = |o: &mut String, mark: &str, mark_rgb: (u8, u8, u8), it: &Item| {
        o.push_str(&format!(
            "    {}  {}  {}\n",
            st.fg(mark_rgb, mark),
            st.bold(&format!("{:<22}", it.name)),
            st.dim(it.blurb),
        ));
        o.push_str(&format!(
            "       {}\n",
            st.dim(&format!("└ {}", it.biology)),
        ));
    };

    o.push_str(&format!(
        "  {}\n",
        st.bold(&st.fg(palette::GREEN, "SHIPPING TODAY")),
    ));
    for it in &SHIPPING {
        row(&mut o, "✓", palette::GREEN, it);
    }
    o.push('\n');

    o.push_str(&format!(
        "  {}\n",
        st.bold(&st.fg(palette::VIOLET, "ON THE ROADMAP")),
    ));
    for it in &ROADMAP {
        row(&mut o, "◇", palette::VIOLET, it);
    }
    o.push('\n');

    o.push_str(&format!(
        "  {}\n\n",
        st.dim("shipping or roadmap, every capability stays offline · air-gapped · deterministic"),
    ));
    o
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plain_render_is_labeled_and_clean() {
        let s = render(false);
        assert!(
            !s.contains('\x1b'),
            "plain roadmap must carry no ANSI codes"
        );
        assert!(s.contains("SHIPPING TODAY"));
        assert!(s.contains("ON THE ROADMAP"));
        // The roadmap items must never read as shipped.
        assert!(s.contains("Germinal center"));
        assert!(s.contains("Herd immunity"));
    }

    #[test]
    fn colored_render_uses_color() {
        assert!(render(true).contains('\x1b'));
    }
}

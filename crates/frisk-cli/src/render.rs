use comfy_table::{Cell, Table};
use owo_colors::OwoColorize;
use recon_core::Report;

pub fn table(r: &Report) {
    println!(
        "\n  frisk  {}    overall: {} ({}/100)\n",
        r.target.bold(),
        r.overall_grade_label.bold(),
        r.overall_score
    );
    let mut t = Table::new();
    t.set_header(vec!["Category", "Grade", "Score", "Findings"]);
    for c in &r.categories {
        let n = r
            .findings
            .iter()
            .filter(|f| f.category.label() == c.category_label)
            .count();
        t.add_row(vec![
            Cell::new(&c.category_label),
            Cell::new(&c.grade_label),
            Cell::new(c.score),
            Cell::new(n),
        ]);
    }
    println!("{t}");
    println!(
        "\n  {} findings · `frisk … --json` for full report\n",
        r.findings.len()
    );
}

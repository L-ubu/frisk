use comfy_table::{Cell, Table};
use owo_colors::OwoColorize;
use recon_core::Report;

pub fn table(r: &Report) {
    println!(
        "\n  frisk  {}    overall: {} ({}/100)\n",
        r.target.bold(),
        r.overall_grade.as_str().bold(),
        r.overall_score
    );
    let mut t = Table::new();
    t.set_header(vec!["Category", "Grade", "Score", "Findings"]);
    for c in &r.categories {
        let n = r
            .findings
            .iter()
            .filter(|f| f.category == c.category)
            .count();
        t.add_row(vec![
            Cell::new(c.category.label()),
            Cell::new(c.grade.as_str()),
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

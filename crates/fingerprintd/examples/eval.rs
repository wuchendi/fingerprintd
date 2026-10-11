//! Runnable offline evaluation harness (fuzzy-matching §10).
//!
//! Replays a labelled fixture through the matching engine and prints the
//! stability and collision rates. With no argument it runs the bundled
//! synthetic fixture; pass a path to a JSON fixture (same schema as
//! `fixtures/eval/synthetic.json`) to score a real labelled corpus.
//!
//! ```text
//! cargo run --example eval                       # bundled synthetic set
//! cargo run --example eval -- path/to/labels.json  # real labelled data
//! ```
//!
//! The synthetic numbers are a directional smoke test, NOT the architecture §3 targets
//! (≥95 % stability, ≤1 % collision); see `fuzzy::eval` for the real-data TODO.

use std::process::ExitCode;

use fingerprintd_server::fuzzy::eval::{Fixture, evaluate};

fn main() -> ExitCode {
    let path = std::env::args().nth(1);

    let (source, fixture) = match &path {
        Some(path) => match std::fs::read_to_string(path) {
            Ok(json) => match Fixture::from_json(&json) {
                Ok(fixture) => (path.as_str(), fixture),
                Err(err) => {
                    eprintln!("failed to parse fixture {path}: {err}");
                    return ExitCode::FAILURE;
                }
            },
            Err(err) => {
                eprintln!("failed to read fixture {path}: {err}");
                return ExitCode::FAILURE;
            }
        },
        None => match Fixture::synthetic() {
            Ok(fixture) => ("<bundled synthetic>", fixture),
            Err(err) => {
                eprintln!("bundled synthetic fixture is malformed: {err}");
                return ExitCode::FAILURE;
            }
        },
    };

    let report = evaluate(&fixture);

    println!("fingerprintd offline evaluation (fuzzy-matching §10)");
    println!("  fixture:            {source}");
    println!("  devices:            {}", report.total_devices);
    println!("  observations:       {}", report.total_observations);
    println!("  revisits:           {}", report.revisits);
    println!("  minted visitorIds:  {}", report.minted_ids);
    println!(
        "  stability rate:     {:.3}  ({}/{} revisits re-linked)",
        report.stability_rate(),
        report.stable_links,
        report.revisits,
    );
    println!(
        "  collision rate:     {:.3}  ({}/{} observations cross-linked)",
        report.collision_rate(),
        report.collisions,
        report.total_observations,
    );

    if path.is_none() {
        println!(
            "\nNOTE: synthetic fixture — directional smoke test only. These are NOT the\n\
             architecture §3 production targets; run against a real labelled corpus to certify them."
        );
    }

    ExitCode::SUCCESS
}

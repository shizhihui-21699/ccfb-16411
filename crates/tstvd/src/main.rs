//! `tstvd` — control-word sharing simulator.
//!
//! Subcommands:
//!   * `run`     — one plant configuration: legit glitches, pirate service, trace.
//!   * `sweep`   — scan period length × relay latency; show the piracy damage
//!                 curve against legitimate glitch rate (always 0).
//!   * `bands`   — trace cost vs band count at a fixed budget.
//!
//! Every number printed comes from the same simulation the tests exercise; the
//! CLI is a window onto it, not a separate code path.

use std::process::ExitCode;

use tstv_cas::params::Params;
use tstvd::report::{format_report, format_trace};
use tstvd::sim::{SimConfig, Simulator};

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cmd = args.first().map(String::as_str).unwrap_or("help");
    match cmd {
        "run" => cmd_run(&args[1..]),
        "sweep" => cmd_sweep(&args[1..]),
        "bands" => cmd_bands(&args[1..]),
        "help" | "-h" | "--help" => {
            print_help();
            ExitCode::SUCCESS
        }
        other => {
            eprintln!("unknown command: {other}\n");
            print_help();
            ExitCode::FAILURE
        }
    }
}

fn print_help() {
    println!(
        "tstvd — control-word sharing: deterrence, tracing, rectification\n\
         \n\
         USAGE\n\
         \x20 tstvd run   [--subs N] [--traitor I] [--period MS] [--lookahead L]\n\
         \x20              [--repeats R] [--bands B] [--loss-ppm P] [--budget BPS]\n\
         \x20              [--measure N] [--seed S]\n\
         \x20 tstvd sweep [--subs N] [--seed S]\n\
         \x20 tstvd bands [--subs N] [--budget BYTES] [--seed S]\n\
         \n\
         All commands are deterministic for a given --seed."
    );
}

fn parse_u64(args: &[String], flag: &str, default: u64) -> u64 {
    args.iter()
        .position(|a| a == flag)
        .and_then(|i| args.get(i + 1))
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn base_config(args: &[String]) -> SimConfig {
    let mut p = Params::default();
    p.period_ms = parse_u64(args, "--period", p.period_ms as u64) as i64;
    p.lookahead_periods = parse_u64(args, "--lookahead", p.lookahead_periods as u64) as usize;
    p.ecm_repeats = parse_u64(args, "--repeats", p.ecm_repeats as u64) as u32;
    p.bands = parse_u64(args, "--bands", p.bands as u64) as u16;
    p.loss_ppm = parse_u64(args, "--loss-ppm", p.loss_ppm as u64) as u32;
    p.ecm_budget_bps = parse_u64(args, "--budget", p.ecm_budget_bps);

    let subs = parse_u64(args, "--subs", 4096) as usize;
    let seed = parse_u64(args, "--seed", 0xC0FF_EE00);
    SimConfig {
        params: p,
        subscribers: subs,
        traitor: (parse_u64(args, "--traitor", (subs * 2 / 3) as u64) as usize)
            .min(subs.saturating_sub(1)),
        warmup_periods: 10,
        measure_periods: parse_u64(args, "--measure", 200),
        seed,
        colluders: 1,
    }
}

fn cmd_run(args: &[String]) -> ExitCode {
    let cfg = base_config(args);
    if let Err(e) = cfg.params.validate() {
        eprintln!("invalid parameters: {e}");
        return ExitCode::FAILURE;
    }
    let mut sim = Simulator::build(cfg);
    let report = sim.run_steady();
    print!("{}", format_report(&report));

    // Tracing budget: the spare ECM bandwidth over one epoch, expressed in bytes.
    let br = sim.headend.bandwidth_report();
    let epoch_ms = sim.headend.params.epoch_periods as i64 * sim.headend.params.period_ms;
    let budget = tstv_cas::bandwidth::BandwidthBudget::new(&br, epoch_ms)
        .epoch_allowance_bytes()
        .max(1_000_000); // floor so a lone probe can run deterministically
    let trace = sim.run_trace(budget);
    print!("{}", format_trace(&trace));
    // Return-channel clone detection: a card cloned into a second box shows up
    // as the same ack from two sources in one epoch.
    if let Some(epoch) = sim.detect_clone(3) {
        println!(
            "\n== Clone detection ===================================\n\
             cloned card flagged at epoch {epoch} (same ack from 2 sources)\n"
        );
    }
    if trace.correct {
        let found = trace.found_card.unwrap();
        let rect = sim.run_rectify(found, 50);
        println!(
            "\n== Rectification =====================================\n\
             revoked card {found} | other-viewer glitches {} | revoked box dark: {} | pirate starved: {}\n",
            rect.other_legit_glitches, rect.revoked_box_went_dark, rect.pirate_starved_after
        );
    }
    ExitCode::SUCCESS
}

fn cmd_sweep(args: &[String]) -> ExitCode {
    let subs = parse_u64(args, "--subs", 1024) as usize;
    let seed = parse_u64(args, "--seed", 0xC0FF_EE00);
    // The knob that matters is the legitimate box's *time* head start,
    // (L-1)*P, against the relay's latency.  Scan both dimensions so the
    // tradeoff is visible: shallow lookahead hurts piracy but risks legit
    // glitches under loss; deep lookahead protects legit but feeds the relay.
    println!("look  period_ms  slack_ms  legit_glitch  pirate_glitch%  ecm_kbit/s");
    for look in [2usize, 3, 4, 5] {
        for period in [250i64, 500, 1000, 2000] {
            let mut p = Params::default();
            p.period_ms = period;
            p.lookahead_periods = look;
            let slack = tstvd::pirate::PirateRelay::slack_ms(&p);
            let cfg = SimConfig {
                params: p,
                subscribers: subs,
                traitor: subs / 2,
                warmup_periods: 4,
                measure_periods: 300,
                seed,
                colluders: 1,
            };
            let mut sim = Simulator::build(cfg);
            let r = sim.run_steady();
            println!(
                "{:>4}  {:>9}  {:>8}  {:>12}  {:>13.1}  {:>11.1}",
                look,
                period,
                slack,
                r.legit_glitches,
                r.pirate_glitch_rate() * 100.0,
                r.bandwidth.ecm_bits_per_sec as f64 / 1000.0
            );
        }
    }
    ExitCode::SUCCESS
}

fn cmd_bands(args: &[String]) -> ExitCode {
    let subs = parse_u64(args, "--subs", 4096) as usize;
    let seed = parse_u64(args, "--seed", 0xC0FF_EE00);
    let budget = parse_u64(args, "--budget", 20_000_000);
    // Larger band count shrinks each band, so the card-suppression phase needs
    // fewer rounds/bytes — but costs more ECM bandwidth (see `sweep`).  Band
    // identification itself is an external fingerprint input, so it shows no
    // round count here.
    println!("bands  band_size  card_rounds  probe_bytes  ecm_kbit/s  correct");
    for bands in [8u16, 16, 32, 64, 128] {
        let mut p = Params::default();
        p.bands = bands;
        let cfg = SimConfig {
            params: p,
            subscribers: subs,
            traitor: subs * 2 / 3,
            warmup_periods: 0,
            measure_periods: 0,
            seed,
            colluders: 1,
        };
        let mut sim = Simulator::build(cfg);
        let r = sim.run_trace(budget);
        let ecm_kbit = sim.headend.bandwidth_report().ecm_bits_per_sec as f64 / 1000.0;
        println!(
            "{:>5}  {:>9}  {:>11}  {:>11}  {:>10.1}  {:>7}",
            bands,
            sim.band_size(),
            r.card_probe_rounds,
            r.total_probe_bytes,
            ecm_kbit,
            r.correct
        );
    }
    ExitCode::SUCCESS
}

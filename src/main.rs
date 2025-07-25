use clap::Parser;
use colored::*;

mod analyzer;
use analyzer::{AnalysisResults, analyze_binary};

/// Binary Hardening Scanner - A tool to inspect compiled binaries for security mitigations
#[derive(Parser, Debug)]
#[clap(author, version, about, long_about = None)]
struct Args {
    /// Path to the binary file to analyze
    #[clap(value_parser)]
    file: String,

    /// Output results in JSON format
    #[clap(long, short = 'j')]
    json: bool,

    /// Verbose output
    #[clap(long, short = 'v')]
    verbose: bool,
}

fn main() {
    let args = Args::parse();

    if args.verbose {
        println!("{}", "Binary Hardening Scanner".bright_blue());
        println!("Analyzing file: {}", args.file);
    }

    match analyze_binary(&args.file, args.verbose) {
        Ok(results) => {
            if args.json {
                println!("{}", serde_json::to_string_pretty(&results).unwrap());
            } else {
                display_results(&results);
            }
        }
        Err(e) => {
            eprintln!("{}: {}", "Error".red(), e);
            std::process::exit(1);
        }
    }
}

fn display_results(results: &AnalysisResults) {
    println!("{}", "Binary Hardening Scanner Report".bright_blue().bold());
    println!("File: {}", results.file_path);
    println!("Format: {}", results.format);
    println!();

    // Display security mitigations status
    println!("Security Mitigations:");
    println!(
        "  NX (No-eXecute): {}",
        if results.nx.enabled {
            "ENABLED".green()
        } else {
            "DISABLED".red()
        }
    );
    if let Some(ref note) = results.nx.note {
        println!("    Note: {}", note);
    }

    println!(
        "  PIE (Position Independent Executable): {}",
        if results.pie.enabled {
            "ENABLED".green()
        } else {
            "DISABLED".red()
        }
    );
    if let Some(ref note) = results.pie.note {
        println!("    Note: {}", note);
    }

    println!(
        "  Stack Canary: {}",
        if results.stack_canary.enabled {
            "ENABLED".green()
        } else {
            "DISABLED".red()
        }
    );
    if let Some(ref note) = results.stack_canary.note {
        println!("    Note: {}", note);
    }

    println!(
        "  RELRO (RELocation Read-Only): {}",
        match results.relro.status.as_str() {
            "Full" => "FULL".green(),
            "Partial" => "PARTIAL".yellow(),
            _ => "NONE".red(),
        }
    );
    if let Some(ref note) = results.relro.note {
        println!("    Note: {}", note);
    }

    // Display fortified functions check
    println!();
    println!("Fortified Functions:");
    println!(
        "  Fortified functions detected: {}",
        if results.fortified_functions.count > 0 {
            results.fortified_functions.count.to_string().green()
        } else {
            "0".red()
        }
    );

    println!(
        "  Unprotected functions detected: {}",
        if results.unprotected_functions.count > 0 {
            results.unprotected_functions.count.to_string().yellow()
        } else {
            "0".green()
        }
    );

    if !results.unprotected_functions.symbols.is_empty() {
        println!("    Unprotected symbols found:");
        for symbol in &results.unprotected_functions.symbols {
            println!("      - {}", symbol);
        }
    }
}

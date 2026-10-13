// Licensed under the Apache License, Version 2.0 <LICENSE or
// http://www.apache.org/licenses/LICENSE-2.0>.
// Copyright 2026 GHSFS. See the NOTICE file for attribution details.

use std::process;

use clap::Parser;

use bin_sentinel::cli::Cli;
use bin_sentinel::commands::dispatch;
use bin_sentinel::error::Result;

fn run() -> Result<()> {
    let cli = Cli::parse();
    dispatch(cli.command)
}

fn main() {
    if let Err(err) = run() {
        eprintln!("Error: {err}");
        process::exit(1);
    }
}

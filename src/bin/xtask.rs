use std::env;
use std::process::{Command, ExitCode};

fn print_usage() {
    eprintln!(
        "Usage:
  cargo run --bin xtask -- precommit [--with-docker]
  cargo run --bin xtask -- ci"
    );
}

fn run_command(program: &str, args: &[&str]) -> Result<(), String> {
    eprintln!("+ {program} {}", args.join(" "));
    let status = Command::new(program)
        .args(args)
        .status()
        .map_err(|error| format!("Failed to run `{program}`: {error}"))?;

    if status.success() {
        Ok(())
    } else {
        Err(format!(
            "Command `{program} {}` exited with status {status}",
            args.join(" ")
        ))
    }
}

fn run_precommit(with_docker: bool) -> Result<(), String> {
    run_command("cargo", &["fmt", "--all", "--", "--check"])?;
    run_command(
        "cargo",
        &[
            "clippy",
            "--all-targets",
            "--all-features",
            "--",
            "-D",
            "warnings",
        ],
    )?;
    run_command("cargo", &["test", "--features", "db"])?;

    if with_docker {
        run_command("cargo", &["test", "--features", "db", "--", "--ignored"])?;
    } else {
        eprintln!("Skipping ignored Docker-backed tests. Use `--with-docker` to include them.");
    }

    Ok(())
}

fn main() -> ExitCode {
    let mut args = env::args().skip(1);
    let Some(command) = args.next() else {
        print_usage();
        return ExitCode::from(2);
    };

    let result = match command.as_str() {
        "precommit" => {
            let rest: Vec<String> = args.collect();
            let mut with_docker = false;

            for arg in rest {
                match arg.as_str() {
                    "--with-docker" => with_docker = true,
                    _ => {
                        return {
                            eprintln!("Unknown option for precommit: {arg}");
                            print_usage();
                            ExitCode::from(2)
                        }
                    }
                }
            }

            run_precommit(with_docker)
        }
        "ci" => run_precommit(true),
        _ => {
            eprintln!("Unknown command: {command}");
            print_usage();
            return ExitCode::from(2);
        }
    };

    match result {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("{error}");
            ExitCode::from(1)
        }
    }
}

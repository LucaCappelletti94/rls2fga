use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::Path;
use std::process::{Command, ExitCode};

fn print_usage() {
    eprintln!(
        "Usage:
  cargo run --bin xtask -- precommit [--locked] [--with-docker]
  cargo run --bin xtask -- ci [--locked] [--with-docker]
  cargo run --bin xtask -- docker-tests [--locked]
  cargo run --bin xtask -- commit-msg <path>"
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

fn cargo_args_with_locked(args: &[&str], locked: bool) -> Vec<String> {
    if !locked {
        return args.iter().map(ToString::to_string).collect();
    }

    let mut out = Vec::with_capacity(args.len() + 1);
    let mut inserted = false;
    for arg in args {
        if !inserted && *arg == "--" {
            out.push("--locked".to_string());
            inserted = true;
        }
        out.push((*arg).to_string());
    }
    if !inserted {
        out.push("--locked".to_string());
    }

    out
}

fn run_cargo(args: &[&str], locked: bool) -> Result<(), String> {
    let args = cargo_args_with_locked(args, locked);
    let arg_refs = args.iter().map(String::as_str).collect::<Vec<_>>();
    run_command("cargo", &arg_refs)
}

fn run_precommit(locked: bool) -> Result<(), String> {
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
    run_cargo(&["test", "--features", "db", "--lib", "--tests"], locked)?;

    Ok(())
}

fn run_docker_tests(locked: bool) -> Result<(), String> {
    run_cargo(
        &["test", "--features", "db", "--tests", "--", "--ignored"],
        locked,
    )
}

fn run_ci(locked: bool, with_docker: bool) -> Result<(), String> {
    run_precommit(locked)?;
    run_cargo(
        &["test", "--all-features", "--no-run", "--lib", "--tests"],
        locked,
    )?;
    run_cargo(&["test", "--doc", "--all-features"], locked)?;

    if with_docker {
        run_docker_tests(locked)?;
    }

    Ok(())
}

fn parse_flags(rest: &[String], allowed: &[&str]) -> Result<HashSet<String>, ExitCode> {
    let allowed_set: HashSet<&str> = allowed.iter().copied().collect();
    let mut flags = HashSet::new();

    for flag in rest {
        if !allowed_set.contains(flag.as_str()) {
            eprintln!("Unknown option: {flag}");
            print_usage();
            return Err(ExitCode::from(2));
        }
        flags.insert(flag.clone());
    }

    Ok(flags)
}

fn validate_commit_message(path: &Path) -> Result<(), String> {
    let raw = fs::read_to_string(path).map_err(|error| {
        format!(
            "Failed to read commit message file {}: {error}",
            path.display()
        )
    })?;

    let mut subject = None;
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        subject = Some(trimmed.to_string());
        break;
    }

    let Some(subject) = subject else {
        return Err("Commit message subject is empty.".to_string());
    };

    let skip_prefixes = ["Merge ", "Revert \"", "fixup! ", "squash! "];
    if skip_prefixes
        .iter()
        .any(|prefix| subject.starts_with(prefix))
    {
        return Ok(());
    }

    if subject.len() > 72 {
        return Err(format!(
            "Commit subject is {} chars (max 72): `{subject}`",
            subject.len()
        ));
    }
    if subject.ends_with('.') {
        return Err("Commit subject must not end with a period.".to_string());
    }
    if !subject.contains(": ") {
        return Err(
            "Commit subject must follow Conventional Commits, e.g. `feat(parser): add xyz`."
                .to_string(),
        );
    }

    let (header, description) = subject.split_once(": ").expect("validated contains ': '");
    if description.trim().is_empty() {
        return Err("Commit description after `: ` must not be empty.".to_string());
    }

    let allowed_types = [
        "build", "chore", "ci", "docs", "feat", "fix", "perf", "refactor", "revert", "style",
        "test",
    ];

    let header = header.strip_suffix('!').unwrap_or(header);
    let commit_type = match header.split_once('(') {
        Some((kind, rest)) => {
            if !rest.ends_with(')') {
                return Err(
                    "Invalid Conventional Commit header: unclosed scope parenthesis.".to_string(),
                );
            }
            kind
        }
        None => header,
    };

    if !allowed_types.contains(&commit_type) {
        return Err(format!(
            "Invalid Conventional Commit type `{commit_type}`. Allowed: {}",
            allowed_types.join(", ")
        ));
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
            let flags = match parse_flags(&rest, &["--locked", "--with-docker"]) {
                Ok(flags) => flags,
                Err(code) => return code,
            };
            let locked = flags.contains("--locked");
            let with_docker = flags.contains("--with-docker");

            if with_docker {
                run_precommit(locked).and_then(|()| run_docker_tests(locked))
            } else {
                run_precommit(locked)
            }
        }
        "docker-tests" => {
            let rest: Vec<String> = args.collect();
            let flags = match parse_flags(&rest, &["--locked"]) {
                Ok(flags) => flags,
                Err(code) => return code,
            };
            run_docker_tests(flags.contains("--locked"))
        }
        "ci" => {
            let rest: Vec<String> = args.collect();
            let flags = match parse_flags(&rest, &["--locked", "--with-docker"]) {
                Ok(flags) => flags,
                Err(code) => return code,
            };
            run_ci(flags.contains("--locked"), flags.contains("--with-docker"))
        }
        "commit-msg" => {
            let rest: Vec<String> = args.collect();
            if rest.len() != 1 {
                eprintln!("commit-msg requires exactly one path argument.");
                print_usage();
                return ExitCode::from(2);
            }
            validate_commit_message(Path::new(&rest[0]))
        }
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

use std::path::PathBuf;
use std::process::Command;
use std::time::{SystemTime, UNIX_EPOCH};

fn unique_temp_file(prefix: &str) -> PathBuf {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock should be after epoch")
        .as_nanos();
    std::env::temp_dir().join(format!("{prefix}_{nanos}.txt"))
}

#[test]
fn xtask_without_command_exits_with_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .output()
        .expect("should run xtask binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected usage exit code 2, got {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Usage:"),
        "expected usage text when no command is provided, got:\n{stderr}"
    );
}

#[test]
fn xtask_unknown_command_exits_with_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("unknown-command")
        .output()
        .expect("should run xtask binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected unknown command exit code 2, got {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Unknown command: unknown-command"),
        "expected unknown command message, got:\n{stderr}"
    );
}

#[test]
fn xtask_commit_msg_requires_exactly_one_path() {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("commit-msg")
        .output()
        .expect("should run xtask binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected missing path exit code 2, got {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("commit-msg requires exactly one path argument."),
        "expected argument-count error, got:\n{stderr}"
    );
}

#[test]
fn xtask_commit_msg_accepts_valid_conventional_subject() {
    let path = unique_temp_file("xtask_commit_ok");
    std::fs::write(&path, "feat(parser): add commit validation\n")
        .expect("should write commit message file");

    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("commit-msg")
        .arg(&path)
        .output()
        .expect("should run xtask binary");

    assert_eq!(
        output.status.code(),
        Some(0),
        "expected valid commit message to pass, got {:?}",
        output.status
    );
}

#[test]
fn xtask_commit_msg_invalid_type_exits_non_zero() {
    let path = unique_temp_file("xtask_commit_bad_type");
    std::fs::write(&path, "invalid(scope): add commit validation\n")
        .expect("should write commit message file");

    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("commit-msg")
        .arg(&path)
        .output()
        .expect("should run xtask binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "expected invalid commit type to fail with exit code 1, got {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Invalid Conventional Commit type"),
        "expected invalid type diagnostic, got:\n{stderr}"
    );
}

#[test]
fn xtask_commit_msg_missing_file_exits_non_zero() {
    let path = unique_temp_file("xtask_commit_missing");

    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("commit-msg")
        .arg(&path)
        .output()
        .expect("should run xtask binary");

    assert_eq!(
        output.status.code(),
        Some(1),
        "expected missing commit file to fail with exit code 1, got {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Failed to read commit message file"),
        "expected missing-file diagnostic, got:\n{stderr}"
    );
}

#[test]
fn xtask_ci_unknown_flag_exits_with_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("ci")
        .arg("--not-a-real-flag")
        .output()
        .expect("should run xtask binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected unknown flag to fail with exit code 2, got {:?}",
        output.status
    );

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(
        stderr.contains("Unknown option: --not-a-real-flag"),
        "expected unknown option diagnostic, got:\n{stderr}"
    );
}

#[test]
fn xtask_precommit_unknown_flag_exits_with_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("precommit")
        .arg("--not-a-real-flag")
        .output()
        .expect("should run xtask binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected unknown flag to fail with exit code 2, got {:?}",
        output.status
    );
}

#[test]
fn xtask_docker_tests_unknown_flag_exits_with_usage_error() {
    let output = Command::new(env!("CARGO_BIN_EXE_xtask"))
        .arg("docker-tests")
        .arg("--not-a-real-flag")
        .output()
        .expect("should run xtask binary");

    assert_eq!(
        output.status.code(),
        Some(2),
        "expected unknown flag to fail with exit code 2, got {:?}",
        output.status
    );
}

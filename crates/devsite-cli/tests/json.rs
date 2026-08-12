use std::process::{Command, Output};
use std::sync::atomic::{AtomicUsize, Ordering};

static NEXT_HOME: AtomicUsize = AtomicUsize::new(0);

fn devsite(args: &[&str]) -> Output {
    let suffix = NEXT_HOME.fetch_add(1, Ordering::Relaxed);
    let home =
        std::env::temp_dir().join(format!("devsite-json-test-{}-{suffix}", std::process::id()));
    let output = Command::new(env!("CARGO_BIN_EXE_devsite"))
        .args(args)
        .env("DEVSITE_HOME", &home)
        .output()
        .unwrap();
    if home.exists() {
        std::fs::remove_dir_all(home).unwrap();
    }
    output
}

fn json(output: &Output) -> serde_json::Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|err| {
        panic!(
            "stdout was not one JSON value: {err}\n{}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

#[test]
fn global_json_flag_structures_success() {
    let output = devsite(&["--json", "status"]);
    assert!(output.status.success());
    let value = json(&output);
    assert_eq!(value["schema_version"], 1);
    assert_eq!(value["ok"], true);
    assert_eq!(value["command"], "status");
    assert_eq!(value["result"]["daemon"]["running"], false);
    assert!(value["result"]["services"].is_array());
    assert!(value["result"]["identity_path"]
        .as_str()
        .unwrap()
        .ends_with("devsite-endpoint.key"));
    assert!(value["result"]["identity"]["public_path"]
        .as_str()
        .unwrap()
        .ends_with("devsite-endpoint.pub"));
    assert!(output.stderr.is_empty());
}

#[test]
fn global_json_flag_works_after_a_subcommand() {
    let output = devsite(&["daemon", "status", "--json"]);
    assert!(output.status.success());
    let value = json(&output);
    assert_eq!(value["command"], "daemon.status");
    assert_eq!(value["result"]["running"], false);
}

#[test]
fn json_structures_runtime_errors() {
    let output = devsite(&["--json", "service", "host", "0"]);
    assert_eq!(output.status.code(), Some(1));
    let value = json(&output);
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["kind"], "runtime");
    assert_eq!(value["error"]["message"], "port 0 cannot be hosted");
    assert!(output.stderr.is_empty());
}

#[test]
fn json_structures_usage_errors() {
    let output = devsite(&["--json", "not-a-command"]);
    assert_eq!(output.status.code(), Some(2));
    let value = json(&output);
    assert_eq!(value["ok"], false);
    assert_eq!(value["error"]["kind"], "usage");
    assert!(value["error"]["suggestions"][0]
        .as_str()
        .unwrap()
        .contains("devsite --help"));
    assert!(output.stderr.is_empty());
}

#[test]
fn json_login_never_prompts() {
    let output = devsite(&["--json", "login"]);
    assert_eq!(output.status.code(), Some(1));
    let value = json(&output);
    assert_eq!(value["error"]["message"], "TOKEN is required with --json");
    assert!(!String::from_utf8_lossy(&output.stdout).contains("token:"));
}

#[test]
fn json_structures_command_help() {
    let output = devsite(&["link", "set", "--json", "--help"]);
    assert!(output.status.success());
    let value = json(&output);
    assert_eq!(value["command"], "help");
    assert_eq!(value["result"]["command"], "link.set");
    assert!(value["result"]["text"]
        .as_str()
        .unwrap()
        .contains("Create or replace a named link"));
}

#[test]
fn human_runtime_errors_end_with_a_recovery_suggestion() {
    let output = devsite(&["service", "host", "0"]);
    assert_eq!(output.status.code(), Some(1));
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("error: port 0 cannot be hosted"));
    assert!(stderr.contains("suggestion: Run `devsite service host --help`"));
}

#[test]
fn doctor_reports_state_and_actions_without_enrollment() {
    let output = devsite(&["doctor", "--json"]);
    assert!(output.status.success());
    let value = json(&output);
    assert_eq!(value["command"], "doctor");
    assert_eq!(value["result"]["healthy"], true);
    assert!(value["result"]["checks"].is_array());
    assert_eq!(value["result"]["actions"][0]["id"], "login");
}

#[test]
fn resources_and_plan_flags_are_discoverable_in_structured_help() {
    let resources = devsite(&["resources", "list", "--json", "--help"]);
    assert!(resources.status.success());
    assert_eq!(json(&resources)["result"]["command"], "resources.list");

    let plan = devsite(&["link", "set", "--json", "--help"]);
    assert!(plan.status.success());
    let text = json(&plan)["result"]["text"].as_str().unwrap().to_string();
    assert!(text.contains("--plan"));
    assert!(text.contains("--dry-run"));
}

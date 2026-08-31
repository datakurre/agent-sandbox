//! The flag -> `podman run` mapping, checked against a stub `podman`.
//!
//! This is the layer between the argument parser and the container runtime:
//! unit tests cover the fragments `launch.rs` and `agents.rs` produce, and the
//! integration suite covers what a real container does with them, but nothing
//! covered *which* fragments the launcher assembles for a given command line.
//! That is what breaks when a flag is added and wired to the wrong block.

mod common;

use common::{World, TEST_IMAGE};

// ── the shape every launch has ──────────────────────────────────────────────

#[test]
fn a_bare_launch_runs_the_default_shell_in_a_disposable_container() {
    let out = World::new().run(&[]);
    let run = out.run_call();

    assert!(
        run.has("--rm"),
        "sandboxes are disposable: {}",
        run.joined()
    );
    assert!(run.has("--userns=keep-id"), "{}", run.joined());
    assert_eq!(run.value_of("--workdir"), Some("/workspace"));
    assert_eq!(run.command(), vec!["bash"]);
}

#[test]
fn every_launch_is_labelled_so_ctl_can_find_it_without_guessing() {
    let out = World::new().run(&["opencode"]);
    let run = out.run_call();
    let labels = run.values_of("--label");

    assert!(labels.contains(&"agent-sandbox.role=sandbox"));
    assert!(labels.contains(&"agent-sandbox.proxy=off"));
    assert!(labels.contains(&"agent-sandbox.runtime=crun"));
    assert!(labels.contains(&"agent-sandbox.command=opencode ."));
}

#[test]
fn every_launch_waits_for_entrypoint_readiness() {
    let out = World::new().run(&["opencode"]);
    let run = out.run_call();

    assert_eq!(
        run.env_value("AGENT_SANDBOX_READY_FILE"),
        Some("/run/agent-sandbox-status/ready")
    );
    assert_eq!(
        run.env_value("AGENT_SANDBOX_READY_ACK_FILE"),
        Some("/run/agent-sandbox-status/ack")
    );
    assert!(
        run.mount_to("/run/agent-sandbox-status")
            .is_some_and(|mount| mount.ends_with(":/run/agent-sandbox-status:rw")),
        "readiness mount missing: {}",
        run.joined()
    );
}

#[test]
fn the_image_is_the_last_argument_before_the_agent_command() {
    let out = World::new().run(&["opencode"]);
    let run = out.run_call();
    let idx = run.0.iter().position(|a| a == TEST_IMAGE).expect("image");

    assert_eq!(
        run.0.len() - idx - 1,
        run.command().len(),
        "everything after the image is the agent's own command line: {}",
        run.joined()
    );
}

#[test]
fn the_launcher_forwards_podmans_exit_code() {
    let world = World::new().podman_reply("run", "", 42);
    assert_eq!(world.run(&["opencode"]).code, Some(42));
}

#[test]
fn an_entrypoint_exit_before_readiness_keeps_diagnostics_and_exit_code() {
    let out = World::new()
        .env("STUB_PODMAN_SKIP_READY", "1")
        .podman_reply("run", "", 42)
        .run(&["opencode"]);

    assert_eq!(out.code, Some(42));
    assert!(
        out.stderr.contains("command exited before the sandbox became ready"),
        "missing early-exit diagnostic:\n{}",
        out.stderr
    );
}

#[test]
fn lifecycle_status_is_silent_for_noninteractive_launches() {
    let out = World::new().run(&["opencode"]);

    assert!(
        !out.stdout.contains("starting sandbox")
            && !out.stderr.contains("starting sandbox")
            && !out.stderr.contains("ready")
            && !out.stderr.contains("closed"),
        "machine-readable launches must not receive lifecycle chatter:\nstdout: {}\nstderr: {}",
        out.stdout,
        out.stderr
    );
}

#[test]
fn name_replaces_the_random_session_word_in_the_container_name() {
    let out = World::new().run(&["--name", "johndoe", "opencode"]);
    let run = out.run_call();

    assert!(run.has("--name"));
    assert_eq!(run.value_of("--name"), Some("agent-sandbox-ws-johndoe"));
    assert_eq!(
        run.values_of("--label")
            .iter()
            .find(|label| label.starts_with("agent-sandbox.command="))
            .copied(),
        Some("agent-sandbox.command=opencode .")
    );
}

#[test]
fn name_without_workspace_still_has_an_explicit_selector_but_no_workspace_label() {
    let out = World::new().run(&["--name=johndoe"]);
    let run = out.run_call();

    assert_eq!(run.value_of("--name"), Some("agent-sandbox-ws-johndoe"));
    assert!(!run
        .values_of("--label")
        .iter()
        .any(|label| label.starts_with("agent-sandbox.workspace=")));
    assert_eq!(run.value_of("--workdir"), Some("/workspace"));
}

// ── --workspace ─────────────────────────────────────────────────────────────

#[test]
fn without_workspace_nothing_from_the_host_is_mounted_and_no_workspace_is_labelled() {
    let out = World::new().run(&[]);
    let run = out.run_call();

    assert!(
        !run.values_of("--label")
            .iter()
            .any(|l| l.starts_with("agent-sandbox.workspace=")),
        "an unmounted sandbox has no workspace to record: {}",
        run.joined()
    );
    assert!(
        run.values_of("-v")
            .iter()
            .all(|m| {
                m.contains("/etc/passwd")
                    || m.contains("/etc/group")
                    || m.contains("/run/agent-sandbox-status")
            }),
        "only synthesized identity and readiness mounts: {}",
        run.joined()
    );
}

#[test]
fn workspace_mounts_the_cwd_under_its_own_basename_and_works_there() {
    let world = World::new();
    let ws = world.workspace().display().to_string();
    let out = world.run(&["--workspace", "opencode"]);
    let run = out.run_call();

    assert_eq!(run.value_of("--workdir"), Some("/workspace/ws"));
    assert_eq!(
        run.mount_to("/workspace/ws"),
        Some(format!("{}:/workspace/ws:rw", ws).as_str()),
        "{}",
        run.joined()
    );
    assert!(run
        .values_of("--label")
        .contains(&format!("agent-sandbox.workspace={}", ws).as_str()));
}

#[test]
fn no_workspace_cancels_a_workspace_that_came_earlier_on_the_line() {
    let out = World::new().run(&["--workspace", "--no-workspace", "opencode"]);
    assert_eq!(out.run_call().value_of("--workdir"), Some("/workspace"));
}

// ── agent selection and its persisted state ─────────────────────────────────

#[test]
fn each_agent_gets_its_own_command() {
    let world = World::new();
    assert_eq!(
        world.run(&["opencode"]).run_call().command(),
        vec!["opencode", "."]
    );
    assert_eq!(
        world.run(&["claude"]).run_call().command(),
        vec!["claude"]
    );
}

#[test]
fn only_the_selected_agents_state_is_mounted() {
    let out = World::new().run(&["claude"]);
    let run = out.run_call();

    assert!(
        run.mount_to("/home/user/.claude").is_some(),
        "{}",
        run.joined()
    );
    assert!(
        run.mount_to("/home/user/.config/opencode").is_none(),
        "another agent's state must not follow along: {}",
        run.joined()
    );
}

#[test]
fn agent_state_files_are_created_on_the_host_so_the_bind_is_a_file_not_a_directory() {
    let world = World::new();
    let out = world.run(&["claude"]);

    assert!(out.run_call().mount_to("/home/user/.claude.json").is_some());
    assert!(
        world.home().join(".claude.json").is_file(),
        "podman would otherwise create a directory in its place"
    );
}

#[test]
fn a_state_file_with_a_seed_is_written_with_that_content_not_empty_braces() {
    let world = World::new();
    let out = world.run(&["pi"]);

    assert!(
        out.run_call()
            .mount_to("/home/user/.pi/agent/models.json")
            .is_some()
    );
    assert_eq!(
        std::fs::read_to_string(world.home().join(".pi/agent/models.json")).unwrap(),
        "SEEDED",
        "a stateFiles entry with a stateFileSeeds default must be written with \
         that content on first launch, not the bare \"{{}}\" other state files get"
    );
}

#[test]
fn a_seeded_state_file_is_never_rewritten_once_it_exists() {
    let world = World::new();
    std::fs::create_dir_all(world.home().join(".pi/agent")).unwrap();
    std::fs::write(world.home().join(".pi/agent/models.json"), "USER EDITED").unwrap();

    world.run(&["pi"]);

    assert_eq!(
        std::fs::read_to_string(world.home().join(".pi/agent/models.json")).unwrap(),
        "USER EDITED",
        "an existing host copy must never be overwritten by the seed"
    );
}

#[test]
fn agent_mounts_all_carries_every_agents_state() {
    let out = World::new().run(&["--agent-mounts", "opencode"]);
    let run = out.run_call();

    assert!(
        run.mount_to("/home/user/.claude").is_some(),
        "{}",
        run.joined()
    );
    assert!(run.mount_to("/home/user/.config/opencode").is_some());
}

#[test]
fn agent_mounts_none_starts_the_agent_with_no_history() {
    let out = World::new().run(&["--no-agent-mounts", "opencode"]);
    let run = out.run_call();

    assert!(
        run.mount_to("/home/user/.config/opencode").is_none(),
        "{}",
        run.joined()
    );
    assert_eq!(run.command(), vec!["opencode", "."]);
}

// ── the writable home ───────────────────────────────────────────────────────

#[test]
fn the_writable_home_subdirectories_are_tmpfs_owned_by_the_mapped_user() {
    let out = World::new().run(&[]);
    let run = out.run_call();
    let mounts = run.values_of("--mount");

    for dir in [".config", ".cache", ".local"] {
        let want = format!("type=tmpfs,dst=/home/user/{},U=true", dir);
        assert!(
            mounts.contains(&want.as_str()),
            "{} is missing from {:?}",
            want,
            mounts
        );
    }
}

// ── SELinux ─────────────────────────────────────────────────────────────────

#[test]
fn selinux_relabels_shared_binds_and_privately_labels_the_synthesized_files() {
    let out = World::new().run(&["--workspace", "--selinux", "opencode"]);
    let run = out.run_call();

    assert!(
        run.mount_to("/workspace/ws").unwrap().ends_with(":rw,z"),
        "a shared bind takes the shared label: {}",
        run.joined()
    );
    assert!(
        run.mount_to("/run/agent-sandbox-status").unwrap().ends_with(":rw,z"),
        "the status dir takes the shared label: {}",
        run.joined()
    );
    assert!(
        run.values_of("-v")
            .iter()
            .find(|m| m.contains(":/etc/passwd:"))
            .unwrap()
            .ends_with(":ro,Z"),
        "a private file takes the private label: {}",
        run.joined()
    );
}

#[test]
fn without_selinux_no_relabelling_flag_is_added() {
    let out = World::new().run(&["--workspace", "opencode"]);
    assert_eq!(
        out.run_call()
            .mount_to("/workspace/ws")
            .unwrap()
            .rsplit(':')
            .next(),
        Some("rw")
    );
}

#[test]
fn selinux_does_not_add_a_relabel_to_the_nix_overlay_mount() {
    let out = World::new().run(&["--nix", "--selinux", "opencode"]);
    let run = out.run_call();

    assert!(
        run.values_of("-v").contains(&"/nix:/nix:O"),
        "the Nix overlay must remain an overlay mount: {}",
        run.joined()
    );
    assert!(
        !run
            .values_of("-v")
            .iter()
            .any(|mount| *mount == "/nix:/nix:O,Z"),
        "SELinux relabeling must not be combined with the Nix overlay: {}",
        run.joined()
    );
}

// ── declared ports ──────────────────────────────────────────────────────────

const PORTS_AGENTS_MD: &str = "\
# Test project

```toml agent-sandbox
[ports]
web = 3000
api = { container = 8080, host = 18080 }
```
";

#[test]
fn declared_ports_are_ignored_until_ports_is_passed() {
    let out = World::new()
        .file("AGENTS.md", PORTS_AGENTS_MD)
        .run(&["--workspace", "opencode"]);

    assert!(
        out.run_call().values_of("-p").is_empty(),
        "AGENTS.md must not open a port on its own: {}",
        out.run_call().joined()
    );
}

#[test]
fn ports_publishes_the_declared_mappings_on_loopback_by_default() {
    let out = World::new().file("AGENTS.md", PORTS_AGENTS_MD).run(&[
        "--workspace",
        "--ports",
        "opencode",
    ]);
    let run = out.run_call();
    let published = run.values_of("-p");

    assert!(
        published.contains(&"127.0.0.1:3000:3000/tcp"),
        "{:?}",
        published
    );
    assert!(
        published.contains(&"127.0.0.1:18080:8080/tcp"),
        "{:?}",
        published
    );
}

#[test]
fn a_wider_bind_needs_the_flag_that_names_the_risk() {
    let agents_md = "\
```toml agent-sandbox
[ports]
web = { container = 3000, bind = \"0.0.0.0\" }
```
";
    let world = World::new().file("AGENTS.md", agents_md);

    let refused = world.run(&["--workspace", "--ports", "opencode"]);
    assert!(
        !refused.reached_podman_run(),
        "a bind past loopback must not be taken from AGENTS.md alone"
    );

    let allowed = world.run(&[
        "--workspace",
        "--ports",
        "--ports-any-interface",
        "opencode",
    ]);
    assert!(allowed
        .run_call()
        .values_of("-p")
        .contains(&"0.0.0.0:3000:3000/tcp"));
}

// ── declared mounts ─────────────────────────────────────────────────────────

#[test]
fn declared_mounts_are_ignored_until_mounts_is_passed() {
    let world = World::new()
        .file(
            "AGENTS.md",
            "```toml agent-sandbox\n[mounts]\n\"data\" = \"/workspace/data\"\n```\n",
        )
        .file("data/keep", "");

    let without = world.run(&["--workspace", "opencode"]);
    assert!(without.run_call().mount_to("/workspace/data").is_none());

    let with = world.run(&["--workspace", "--mounts", "opencode"]);
    assert!(
        with.run_call().mount_to("/workspace/data").is_some(),
        "{}",
        with.run_call().joined()
    );
}

#[test]
fn a_declared_mount_keeps_the_options_it_declared() {
    let out = World::new()
        .file(
            "AGENTS.md",
            "```toml agent-sandbox\n[mounts]\n\"cache\" = { destination = \"/tmp/cache\", options = \"ro\" }\n```\n",
        )
        .file("cache/keep", "")
        .run(&["--workspace", "--mounts", "opencode"]);

    assert!(
        out.run_call()
            .mount_to("/tmp/cache")
            .unwrap()
            .ends_with(":ro"),
        "{}",
        out.run_call().joined()
    );
}

// ── passthrough ─────────────────────────────────────────────────────────────

#[test]
fn podman_args_reach_podman_verbatim_and_after_the_launchers_own() {
    let out = World::new().run(&["--podman-args", "-p", "9000:9000", "--", "opencode"]);
    let run = out.run_call();

    assert!(
        run.values_of("-p").contains(&"9000:9000"),
        "an operator's publish is not rewritten to loopback: {}",
        run.joined()
    );

    let passthrough = run.0.iter().position(|a| a == "9000:9000").unwrap();
    let image = run.0.iter().position(|a| a == TEST_IMAGE).unwrap();
    assert!(
        passthrough < image,
        "passthrough belongs to podman, not the agent"
    );
}

#[test]
fn env_is_forwarded_in_both_spellings() {
    let out = World::new().run(&["-e", "FOO=1", "--env=BAR=2", "opencode"]);
    let run = out.run_call();

    assert_eq!(run.env_value("FOO"), Some("1"));
    assert_eq!(run.env_value("BAR"), Some("2"));
}

#[test]
fn common_podman_args_are_forwarded_in_both_available_spellings() {
    let out = World::new().run(&[
        "-v",
        "cache:/cache",
        "--volume=src:/src:ro",
        "--mount",
        "type=tmpfs,dst=/tmp/work",
        "-p",
        "127.0.0.1:9000:9000",
        "--publish=127.0.0.1:9001:9001",
        "--add-host",
        "local.test:127.0.0.1",
        "--env-file=/tmp/environment",
        "--hostname",
        "sandbox-test",
        "--tmpfs=/tmp/another:rw",
        "opencode",
    ]);
    let run = out.run_call();

    assert!(run.has_pair("-v", "cache:/cache"), "{}", run.joined());
    assert!(run.has_pair("-v", "src:/src:ro"), "{}", run.joined());
    assert!(
        run.has_pair("--mount", "type=tmpfs,dst=/tmp/work"),
        "{}",
        run.joined()
    );
    assert!(
        run.has_pair("-p", "127.0.0.1:9000:9000"),
        "{}",
        run.joined()
    );
    assert!(
        run.has_pair("-p", "127.0.0.1:9001:9001"),
        "{}",
        run.joined()
    );
    assert!(
        run.has_pair("--add-host", "local.test:127.0.0.1"),
        "{}",
        run.joined()
    );
    assert!(run.has_pair("--env-file", "/tmp/environment"), "{}", run.joined());
    assert!(run.has_pair("--hostname", "sandbox-test"), "{}", run.joined());
    assert!(run.has_pair("--tmpfs", "/tmp/another:rw"), "{}", run.joined());
}

#[test]
fn common_short_podman_args_accept_attached_values() {
    let out = World::new().run(&["-vcache:/cache", "-p9000:9000", "opencode"]);
    let run = out.run_call();

    assert!(run.has_pair("-v", "cache:/cache"), "{}", run.joined());
    assert!(run.has_pair("-p", "9000:9000"), "{}", run.joined());
}

#[test]
fn the_terminal_type_follows_the_host_into_the_container() {
    let out = World::new()
        .env("TERM", "screen-256color")
        .run(&["opencode"]);
    assert_eq!(out.run_call().env_value("TERM"), Some("screen-256color"));
}

// ── refusals: the flags that must not be silently combined ──────────────────

#[test]
fn proxy_refuses_host_networking_smuggled_through_podman_args() {
    for spec in [
        vec!["--podman-args", "--network", "host", "--"],
        vec!["--podman-args", "--network=host", "--"],
    ] {
        let mut args = vec!["--workspace", "--proxy"];
        args.extend(spec.iter());
        args.push("opencode");

        let out = World::new().run(&args);
        assert!(
            !out.reached_podman_run(),
            "host networking defeats the firewall entirely: {:?}",
            args
        );
        assert!(out.stderr.contains("host networking"), "{}", out.stderr);
    }
}

#[test]
fn krun_and_podman_are_refused_together() {
    let out = World::new().run(&["--krun", "--podman", "opencode"]);

    assert!(!out.reached_podman_run());
    assert!(out.stderr.contains("--krun"), "{}", out.stderr);
}

#[test]
fn an_unknown_flag_stops_the_launch_rather_than_reaching_podman() {
    let out = World::new().run(&["--definitely-not-a-flag", "opencode"]);

    assert!(!out.reached_podman_run());
    assert!(out.failed());
    assert!(
        out.stderr.contains("is not an agent-sandbox flag"),
        "{}",
        out.stderr
    );
}

#[test]
fn proxy_log_flag_is_removed() {
    let out = World::new().run(&["--proxy-log", "denied", "opencode"]);

    assert!(!out.reached_podman_run());
    assert!(out.failed());
    assert!(
        out.stderr.contains("--proxy-log") && out.stderr.contains("not an agent-sandbox flag"),
        "{}",
        out.stderr
    );
}

#[test]
fn a_removed_flag_says_what_replaced_it() {
    let out = World::new().run(&["--port", "3000", "opencode"]);

    assert!(!out.reached_podman_run());
    assert!(
        out.stderr.contains("[ports]") && out.stderr.contains("--ports"),
        "a removed flag should name its replacement: {}",
        out.stderr
    );
}

#[test]
fn an_invalid_network_block_refuses_the_launch_under_proxy() {
    let out = World::new()
        .file(
            "AGENTS.md",
            "```toml agent-sandbox\n[network]\nallowed_hostz = [\"example.com:443\"]\n```\n",
        )
        .run(&["--workspace", "--proxy", "opencode"]);

    assert!(
        !out.reached_podman_run(),
        "a policy that does not parse must never be downgraded to no policy"
    );
    assert!(out.failed());
}

#[test]
fn network_rules_without_proxy_warn_rather_than_pretending_to_enforce() {
    let out = World::new()
        .file(
            "AGENTS.md",
            "```toml agent-sandbox\n[network]\nallowed_hosts = [\"example.com:443\"]\n```\n",
        )
        .run(&["--workspace", "opencode"]);

    assert!(
        out.reached_podman_run(),
        "no proxy is not an error, only a warning"
    );
    assert!(
        out.stderr.contains("--proxy"),
        "the warning must name the flag that would enforce them: {}",
        out.stderr
    );
    assert!(
        out.run_call()
            .values_of("--label")
            .contains(&"agent-sandbox.proxy=off"),
        "and the container records that it is unproxied"
    );
}

// ── krun ────────────────────────────────────────────────────────────────────

#[test]
fn krun_selects_the_vm_runtime_and_records_it_on_the_container() {
    let out = World::new().run(&[
        "--krun",
        "--krun-memory",
        "4096",
        "--krun-cpus",
        "2",
        "opencode",
    ]);
    let run = out.run_call();

    assert_eq!(run.value_of("--runtime"), Some("krun"));
    assert!(run
        .values_of("--label")
        .contains(&"agent-sandbox.runtime=krun"));
    let annotations = run.values_of("--annotation");
    assert!(
        annotations.contains(&"krun.ram_mib=4096"),
        "{:?}",
        annotations
    );
    assert!(annotations.contains(&"krun.cpus=2"), "{:?}", annotations);
}

// ── privileged ──────────────────────────────────────────────────────────────

#[test]
fn privileged_is_passed_through_and_is_off_by_default() {
    let world = World::new();
    assert!(!world.run(&["opencode"]).run_call().has("--privileged"));
    assert!(world
        .run(&["--privileged", "opencode"])
        .run_call()
        .has("--privileged"));
}

// ── help ────────────────────────────────────────────────────────────────────

#[test]
fn help_never_starts_a_container() {
    let out = World::new().run(&["--help"]);

    assert!(!out.reached_podman_run());
    assert_eq!(out.code, Some(0));
    assert!(out.stdout.contains("--workspace"), "{}", out.stdout);
}

#[test]
fn help_lists_exactly_the_agents_the_catalog_declares() {
    let out = World::new()
        .env("AGENT_SANDBOX_AGENT_SPECS", "solo\t[\"solo\"]\t[]\t[]")
        .run(&["--help"]);

    assert!(out.stdout.contains("solo"), "{}", out.stdout);
    assert!(
        !out.stdout.contains("claude"),
        "the help text must come from the catalog, not a second copy of it"
    );
}

#[test]
fn help_options_share_a_description_column() {
    let out = World::new().run(&["--help"]);

    for line in out.stdout.lines().filter(|line| {
        line.starts_with("  --") || line.starts_with("  -e,")
    }) {
        assert!(
            line.len() > 45,
            "help option is missing its aligned description: {line:?}"
        );
        assert!(
            line.as_bytes()[45] != b' ',
            "help option description does not start at column 45: {line:?}"
        );
    }
}

#[test]
fn ctl_help_commands_share_a_description_column() {
    let out = World::new().run(&["ctl", "--help"]);

    assert_eq!(out.code, Some(0));
    for line in out.stdout.lines().filter(|line| {
        line.starts_with("  ") && !line.starts_with("  -") && line.contains("     ")
    }) {
        assert_eq!(
            line.find(|character: char| character.is_ascii_uppercase()),
            Some(11),
            "ctl command description is not aligned: {line:?}"
        );
    }
}

// ── prompt / json mode ──────────────────────────────────────────────────────
//
// `--programmatic` was one flag doing three things at once: source the agent's
// prompt from stdin, require an agent, and switch stdout to a JSON envelope. It's
// now `--prompt -` (source + agent requirement) and `--json` (output format),
// independently. `--json --prompt -` together reproduce the old behaviour exactly
// -- most of these tests just combine the two, same as `--programmatic` used to.

#[test]
fn json_prompt_mode_appends_agent_prompt_arguments_and_omits_tty() {
    let out = World::new().run(&["--json", "--prompt", "-", "claude"]);
    let run = out.run_call();

    assert_eq!(run.command(), vec!["claude", "-p", "-"]);
    assert!(!run.has("--tty"), "json/prompt mode must omit --tty");
    let json: serde_json::Value =
        serde_json::from_str(&out.stdout).expect("valid JSON stdout");
    assert_eq!(json["type"], "exit");
    assert_eq!(json["status"], 0);
}

#[test]
fn prompt_mode_appends_agent_prompt_arguments_and_omits_tty_without_json() {
    // `--prompt` alone (no `--json`) is a legitimate combination: pipe a prompt
    // in, get the agent's own (human-oriented or already-structured) output back
    // untouched, with no envelope wrapping it.
    let out = World::new().run(&["--prompt", "-", "claude"]);
    let run = out.run_call();

    assert_eq!(run.command(), vec!["claude", "-p", "-"]);
    assert!(!run.has("--tty"), "--prompt must omit --tty even without --json");
}

#[test]
fn prompt_only_supports_stdin() {
    let out = World::new().run(&["--prompt", "literal-text", "claude"]);

    assert_eq!(out.code, Some(1));
    assert!(!out.reached_podman_run());
    assert!(
        out.stderr.contains("--prompt only supports '-'"),
        "unexpected stderr: {}",
        out.stderr
    );
}

#[test]
fn json_prompt_mode_with_opencode_appends_correct_prompt_flags() {
    let out = World::new().run(&["--json", "--prompt", "-", "opencode"]);
    let run = out.run_call();

    assert_eq!(run.command(), vec!["opencode", ".", "--prompt", "-"]);
}

#[test]
fn json_prompt_mode_with_model_appends_model_flags() {
    let out = World::new().run(&["--json", "--prompt", "-", "--model", "sonnet", "claude"]);
    let run = out.run_call();

    assert_eq!(run.command(), vec!["claude", "-p", "-", "--model", "sonnet"]);
}

#[test]
fn model_without_prompt_fails() {
    let out = World::new().run(&["--model", "sonnet", "claude"]);

    assert_eq!(out.code, Some(1));
    assert!(!out.reached_podman_run());
    assert!(
        out.stderr.contains("--model requires --prompt"),
        "unexpected stderr: {}",
        out.stderr
    );
}

#[test]
fn json_prompt_mode_with_max_ai_credits_appends_flags() {
    let out = World::new().run(&["--json", "--prompt", "-", "--max-ai-credits", "50", "copilot"]);
    let run = out.run_call();

    assert_eq!(run.command(), vec!["copilot", "-p", "-", "--max-ai-credits", "50"]);
}

#[test]
fn max_ai_credits_without_prompt_fails() {
    let out = World::new().run(&["--max-ai-credits", "50", "copilot"]);

    assert_eq!(out.code, Some(1));
    assert!(!out.reached_podman_run());
    assert!(
        out.stderr.contains("--max-ai-credits requires --prompt"),
        "unexpected stderr: {}",
        out.stderr
    );
}

#[test]
fn max_ai_credits_rejects_unsupported_agent() {
    let out = World::new().run(&["--json", "--prompt", "-", "--max-ai-credits", "50", "opencode"]);

    assert_eq!(out.code, Some(1));
    assert!(!out.reached_podman_run());
    let json: serde_json::Value =
        serde_json::from_str(&out.stdout).expect("valid JSON error output");
    assert_eq!(json["status"], 1);
    assert!(
        json["stderr"]
            .as_str()
            .unwrap()
            .contains("does not support the --max-ai-credits flag"),
        "unexpected stderr in JSON: {:?}",
        json["stderr"]
    );
}

#[test]
fn max_ai_credits_rejects_non_numeric_value() {
    let out = World::new().run(&["--json", "--prompt", "-", "--max-ai-credits", "fifty", "copilot"]);

    assert_eq!(out.code, Some(1));
    assert!(!out.reached_podman_run());
    let json: serde_json::Value =
        serde_json::from_str(&out.stdout).expect("valid JSON error output");
    assert_eq!(json["status"], 1);
    assert!(
        json["stderr"]
            .as_str()
            .unwrap()
            .contains("--max-ai-credits must be a positive integer"),
        "unexpected stderr in JSON: {:?}",
        json["stderr"]
    );
}

#[test]
fn prompt_mode_requires_an_agent() {
    let out = World::new().run(&["--json", "--prompt", "-"]);

    assert_eq!(out.code, Some(1));
    assert!(!out.reached_podman_run());
    let json: serde_json::Value =
        serde_json::from_str(&out.stdout).expect("valid JSON error output");
    assert_eq!(json["status"], 1);
    assert!(
        json["stderr"]
            .as_str()
            .unwrap()
            .contains("--prompt requires an agent to be specified"),
        "unexpected stderr in JSON: {:?}",
        json["stderr"]
    );
}

#[test]
fn prompt_mode_rejects_agent_without_prompt_args() {
    let out = World::new()
        .env("AGENT_SANDBOX_AGENT_SPECS", "solo\t[\"solo\"]\t[]\t[]")
        .run(&["--json", "--prompt", "-", "solo"]);

    assert_eq!(out.code, Some(1));
    assert!(!out.reached_podman_run());
    let json: serde_json::Value =
        serde_json::from_str(&out.stdout).expect("valid JSON error output");
    assert_eq!(json["status"], 1);
    assert!(
        json["stderr"]
            .as_str()
            .unwrap()
            .contains("does not support --prompt (stdin) execution"),
        "unexpected stderr in JSON: {:?}",
        json["stderr"]
    );
}

#[test]
fn json_prompt_mode_on_exit_failure_returns_json_with_nonzero_status() {
    let world = World::new().podman_reply("run", "", 42);
    let out = world.run(&["--json", "--prompt", "-", "claude"]);

    assert_eq!(out.code, Some(42));
    let json: serde_json::Value =
        serde_json::from_str(&out.stdout).expect("valid JSON error output");
    assert_eq!(json["type"], "exit");
    assert_eq!(json["status"], 42);
}


#[test]
fn json_prompt_mode_with_pi_appends_correct_prompt_flags() {
    let out = World::new().run(&["--json", "--prompt", "-", "pi"]);
    let run = out.run_call();

    assert_eq!(run.command(), vec!["pi", "-p", "--mode", "json"]);
}

#[test]
fn prompt_value_that_names_a_ctl_subcommand_is_not_dispatched_to_ctl() {
    // The pre-scan that spots a `ctl` subcommand has to know `--prompt` takes a
    // value, or `--prompt status` reads as "run ctl status" and the bad value is
    // never reported.
    let out = World::new().run(&["--prompt", "status", "claude"]);

    assert_eq!(out.code, Some(1));
    assert!(
        out.stderr.contains("--prompt only supports '-'"),
        "unexpected stderr: {}",
        out.stderr
    );
}

// ── per-agent flag mappings ─────────────────────────────────────────────────
//
// --session/--fork/--provider used to be pushed through verbatim, on the
// assumption every agent spells them the way pi does. They do not: claude
// resumes with --resume, copilot with --session-id, antigravity with
// --conversation, and opencode's own --fork is a boolean qualifying a resume
// rather than an id-taking flag. Each is declared per agent in agents.nix now,
// and an agent that declares nothing refuses the run.

#[test]
fn session_uses_the_agents_own_spelling() {
    let out = World::new().run(&["--json", "--prompt", "-", "--session", "abc123", "claude"]);

    assert_eq!(
        out.run_call().command(),
        vec!["claude", "-p", "-", "--resume", "abc123"]
    );
}

#[test]
fn a_mapping_with_a_placeholder_wraps_the_value() {
    // claude forks by resuming with a new id: `--resume ID --fork-session`. The
    // value lands where `{}` is, not at the end.
    let out = World::new().run(&["--json", "--prompt", "-", "--fork", "abc123", "claude"]);

    assert_eq!(
        out.run_call().command(),
        vec!["claude", "-p", "-", "--resume", "abc123", "--fork-session"]
    );
}

#[test]
fn a_mapping_without_a_placeholder_appends_the_value() {
    let out = World::new().run(&["--json", "--prompt", "-", "--session", "abc123", "pi"]);

    assert_eq!(
        out.run_call().command(),
        vec!["pi", "-p", "--mode", "json", "--session", "abc123"]
    );
}

#[test]
fn provider_is_refused_for_an_agent_that_declares_no_mapping() {
    let out = World::new().run(&["--json", "--prompt", "-", "--provider", "anthropic", "claude"]);

    assert_eq!(out.code, Some(1));
    assert!(!out.reached_podman_run());
    let json: serde_json::Value =
        serde_json::from_str(&out.stdout).expect("valid JSON error output");
    assert!(
        json["stderr"]
            .as_str()
            .unwrap()
            .contains("does not support the --provider flag"),
        "unexpected stderr in JSON: {:?}",
        json["stderr"]
    );
}

#[test]
fn fork_is_refused_for_an_agent_that_declares_no_mapping() {
    let out = World::new().run(&["--json", "--prompt", "-", "--fork", "abc123", "copilot"]);

    assert_eq!(out.code, Some(1));
    assert!(!out.reached_podman_run());
    let json: serde_json::Value =
        serde_json::from_str(&out.stdout).expect("valid JSON error output");
    assert!(
        json["stderr"]
            .as_str()
            .unwrap()
            .contains("does not support the --fork flag"),
        "unexpected stderr in JSON: {:?}",
        json["stderr"]
    );
}

#[test]
fn provider_reaches_an_agent_that_does_declare_it() {
    let out = World::new().run(&["--json", "--prompt", "-", "--provider", "openai", "pi"]);

    assert_eq!(
        out.run_call().command(),
        vec!["pi", "-p", "--mode", "json", "--provider", "openai"]
    );
}

// ── the catalog the binary ships with ───────────────────────────────────────
//
// Everything above runs against `TEST_AGENT_SPECS`, which is a stand-in. These
// run with `AGENT_SANDBOX_AGENT_SPECS` unset, so they pin the real arguments the
// binary falls back to -- the copy of `agents.nix` that has drifted from it
// before. Each argv here was checked against the agent's own `--help`.

#[test]
fn the_built_in_catalog_gives_pi_no_message_positional() {
    // `pi [options] [@files...] [messages...]`: a bare positional is a *message*,
    // and pi concatenates the first one onto the piped prompt with no separator,
    // so a "." here would reach the model as part of the prompt.
    let out = World::new()
        .env_unset("AGENT_SANDBOX_AGENT_SPECS")
        .run(&["--json", "--prompt", "-", "pi"]);

    assert_eq!(out.run_call().command(), vec!["pi", "-p", "--mode", "json"]);
}

#[test]
fn the_built_in_catalog_gives_pi_no_stdin_marker() {
    // pi has no "-" stdin marker; passing one is `Error: Unknown option: -`.
    let out = World::new()
        .env_unset("AGENT_SANDBOX_AGENT_SPECS")
        .run(&["--json", "--prompt", "-", "pi"]);

    assert!(
        !out.run_call().command().contains(&"-"),
        "pi must not be handed a bare '-': {:?}",
        out.run_call().command()
    );
}

#[test]
fn the_built_in_catalog_spells_session_per_agent() {
    // Each of these was read off the agent's own --help, and none of them is the
    // launcher's own `--session`.
    for (agent, expected) in [
        (
            "claude",
            vec!["claude", "-p", "-", "--output-format", "json", "--resume", "s1"],
        ),
        (
            "copilot",
            vec![
                "copilot",
                "-p",
                "-",
                "--output-format",
                "json",
                "--session-id",
                "s1",
            ],
        ),
        (
            "antigravity",
            vec![
                "agy",
                "--prompt",
                "-",
                "--output-format",
                "json",
                "--conversation",
                "s1",
            ],
        ),
        (
            "opencode",
            vec!["opencode", "run", "--format", "json", "--session", "s1"],
        ),
    ] {
        let out = World::new()
            .env_unset("AGENT_SANDBOX_AGENT_SPECS")
            .run(&["--json", "--prompt", "-", "--session", "s1", agent]);
        assert_eq!(out.run_call().command(), expected, "for agent {}", agent);
    }
}

#[test]
fn the_built_in_catalog_refuses_session_for_codex() {
    // Resuming codex is `codex exec resume <id> [PROMPT]`, a subcommand that has
    // to precede the prompt argument, which an appended mapping cannot express.
    // Refused rather than mis-spelled.
    let out = World::new()
        .env_unset("AGENT_SANDBOX_AGENT_SPECS")
        .run(&["--json", "--prompt", "-", "--session", "s1", "codex"]);

    assert_eq!(out.code, Some(1));
    assert!(!out.reached_podman_run());
    let json: serde_json::Value =
        serde_json::from_str(&out.stdout).expect("valid JSON error output");
    assert!(
        json["stderr"]
            .as_str()
            .unwrap()
            .contains("does not support the --session flag"),
        "unexpected stderr in JSON: {:?}",
        json["stderr"]
    );
}

#[test]
fn the_built_in_catalog_no_longer_claims_copilot_takes_max_ai_credits() {
    // github-copilot-cli 1.0.61 answers `--max-ai-credits` with "error: unknown
    // option". The mapping is gone until the flag comes back, so the launcher
    // refuses instead of building an argv copilot rejects.
    let out = World::new()
        .env_unset("AGENT_SANDBOX_AGENT_SPECS")
        .run(&["--json", "--prompt", "-", "--max-ai-credits", "50", "copilot"]);

    assert_eq!(out.code, Some(1));
    assert!(!out.reached_podman_run());
    let json: serde_json::Value =
        serde_json::from_str(&out.stdout).expect("valid JSON error output");
    assert!(
        json["stderr"]
            .as_str()
            .unwrap()
            .contains("does not support the --max-ai-credits flag"),
        "unexpected stderr in JSON: {:?}",
        json["stderr"]
    );
}

#[test]
fn the_built_in_catalog_runs_codex_non_interactively_through_exec() {
    // codex's non-interactive entry point is the `exec` subcommand, whose PROMPT
    // argument documents "-" as read-from-stdin. codex has no `-p/--print` -- its
    // `-p` is `--profile <CONFIG_PROFILE_V2>`.
    let out = World::new()
        .env_unset("AGENT_SANDBOX_AGENT_SPECS")
        .run(&["--json", "--prompt", "-", "codex"]);

    assert_eq!(
        out.run_call().command(),
        vec!["codex", "exec", "-", "--json"]
    );
}

// ── agent-side json output (agents.nix `jsonArgs`) ─────────────────────────
//
// `--json` is a statement about the run's stdout, and an agent that can emit
// JSON itself is part of that: it gets its own output flags, and the closing
// envelope then carries what it said as JSON rather than as a string of escaped
// JSON that the caller would have to parse a second time.

#[test]
fn json_prompt_mode_asks_an_agent_that_can_speak_json_to_do_so() {
    let out = World::new().run(&["--json", "--prompt", "-", "pi"]);

    assert_eq!(out.run_call().command(), vec!["pi", "-p", "--mode", "json"]);
}

#[test]
fn prompt_mode_without_json_leaves_the_agent_in_its_default_output_mode() {
    // The output flags follow the launcher's --json, not --prompt: a piped
    // prompt whose answer a human reads back should not arrive as an event
    // stream.
    let out = World::new().run(&["--prompt", "-", "pi"]);

    assert_eq!(out.run_call().command(), vec!["pi", "-p"]);
}

#[test]
fn an_agent_with_no_json_output_flags_is_still_run() {
    // Unlike --model or --session, nothing the user spelled is being dropped
    // here, so there is nothing to refuse: the agent runs in its own default
    // mode and its output is reported as the text it is.
    let out = World::new().run(&["--json", "--prompt", "-", "claude"]);

    assert_eq!(out.code, Some(0));
    assert_eq!(out.run_call().command(), vec!["claude", "-p", "-"]);
}

#[test]
fn json_prompt_mode_embeds_an_agents_own_json_output_unquoted() {
    let events = "{\"type\":\"agent_start\"}\n{\"type\":\"agent_end\",\"cost\":0.5}\n";
    let world = World::new().podman_reply("run", events, 0);
    let out = world.run(&["--json", "--prompt", "-", "pi"]);

    let json: serde_json::Value = serde_json::from_str(&out.stdout).expect("valid JSON stdout");
    assert_eq!(json["stdout_format"], "json");
    // One array element per JSONL event, reachable directly -- no second parse,
    // no unescaping.
    assert_eq!(json["stdout"][0]["type"], "agent_start");
    assert_eq!(json["stdout"][1]["cost"], 0.5);
    assert_eq!(json["stdout"].as_array().expect("an array").len(), 2);
}

#[test]
fn json_prompt_mode_reports_a_text_only_agents_output_as_a_string() {
    let world = World::new().podman_reply("run", "plain words\n", 0);
    let out = world.run(&["--json", "--prompt", "-", "claude"]);

    let json: serde_json::Value = serde_json::from_str(&out.stdout).expect("valid JSON stdout");
    assert_eq!(json["stdout_format"], "text");
    assert_eq!(json["stdout"], "plain words\n");
}

#[test]
fn output_that_does_not_parse_as_json_falls_back_to_a_string() {
    // An agent can die before its first event, or print a warning onto stdout.
    // Reporting that as the text it is beats dropping it.
    let world = World::new().podman_reply("run", "Killed\n", 0);
    let out = world.run(&["--json", "--prompt", "-", "pi"]);

    let json: serde_json::Value = serde_json::from_str(&out.stdout).expect("valid JSON stdout");
    assert_eq!(json["stdout_format"], "text");
    assert_eq!(json["stdout"], "Killed\n");
}

#[test]
fn an_agent_that_printed_nothing_still_reports_an_empty_json_array() {
    let world = World::new().podman_reply("run", "", 0);
    let out = world.run(&["--json", "--prompt", "-", "pi"]);

    let json: serde_json::Value = serde_json::from_str(&out.stdout).expect("valid JSON stdout");
    assert_eq!(json["stdout_format"], "json");
    assert_eq!(json["stdout"], serde_json::json!([]));
}

#[test]
fn the_built_in_catalog_asks_every_agent_for_its_own_json_output() {
    // Each spelling was read off the agent's own --help. Every agent in the
    // catalog has one today, so `--json` never has to fall back to quoting an
    // agent's text.
    for (agent, expected) in [
        ("opencode", vec!["--format", "json"]),
        ("claude", vec!["--output-format", "json"]),
        ("copilot", vec!["--output-format", "json"]),
        ("antigravity", vec!["--output-format", "json"]),
        ("codex", vec!["--json"]),
        ("pi", vec!["--mode", "json"]),
    ] {
        let out = World::new()
            .env_unset("AGENT_SANDBOX_AGENT_SPECS")
            .run(&["--json", "--prompt", "-", agent]);
        let run = out.run_call();
        let command = run.command();
        let tail = &command[command.len() - expected.len()..];
        assert_eq!(tail, expected.as_slice(), "for agent {}", agent);
    }
}

#[test]
fn the_built_in_catalog_runs_opencode_non_interactively_through_run() {
    // `opencode run`, not the TUI's `--prompt`: the top-level command took "-"
    // as the prompt *text* and still tried to start the interface, and `run` is
    // the only form that has `--format json`.
    let out = World::new()
        .env_unset("AGENT_SANDBOX_AGENT_SPECS")
        .run(&["--json", "--prompt", "-", "opencode"]);

    assert_eq!(
        out.run_call().command(),
        vec!["opencode", "run", "--format", "json"]
    );
}

#[test]
fn the_built_in_catalog_runs_graph_agent_interactively_as_tui() {
    let out = World::new()
        .env_unset("AGENT_SANDBOX_AGENT_SPECS")
        .run(&["graph-agent"]);

    assert_eq!(out.run_call().command(), vec!["graph-agent", "tui"]);
    assert!(out.run_call().mount_to("/home/user/.config/graph-agent").is_some());
    assert!(out.run_call().mount_to("/home/user/.local/state/graph-agent").is_some());
    assert!(out.run_call().mount_to("/home/user/.pi").is_some());
}

#[test]
fn the_built_in_catalog_refuses_prompt_for_graph_agent() {
    let out = World::new()
        .env_unset("AGENT_SANDBOX_AGENT_SPECS")
        .run(&["--json", "--prompt", "-", "graph-agent"]);

    assert_eq!(out.code, Some(1));
    assert!(!out.reached_podman_run());
    let json: serde_json::Value =
        serde_json::from_str(&out.stdout).expect("valid JSON error output");
    assert!(
        json["stderr"]
            .as_str()
            .unwrap()
            .contains("does not support --prompt (stdin) execution"),
        "unexpected stderr in JSON: {:?}",
        json["stderr"]
    );
}

// ── json mode on a plain command (no agent, no --prompt) ───────────────────
//
// This is the case `--programmatic` never covered: `--json` on a `-- COMMAND`
// wraps a deterministic command's output the same way, but streams one
// {type:"output"} object per line as it happens rather than buffering the whole
// run, so a long command still tails live instead of going silent until exit.

#[test]
fn json_mode_on_a_plain_command_streams_output_lines_and_a_final_exit_summary() {
    let world = World::new().podman_reply("run", "first\nsecond\n", 0);
    let out = world.run(&["--json", "--", "echo", "hi"]);

    assert_eq!(out.code, Some(0));
    let lines: Vec<serde_json::Value> = out
        .stdout
        .lines()
        .map(|l| serde_json::from_str(l).expect("each stdout line is one JSON object"))
        .collect();

    let outputs: Vec<&str> = lines
        .iter()
        .filter(|v| v["type"] == "output")
        .map(|v| v["line"].as_str().unwrap())
        .collect();
    assert_eq!(outputs, vec!["first", "second"]);

    let exit = lines
        .iter()
        .find(|v| v["type"] == "exit")
        .expect("a final exit summary line");
    assert_eq!(exit["status"], 0);
    // The lines already went out as {type:"output"} objects above; the summary
    // doesn't repeat them.
    assert_eq!(exit["stdout"], "");
    assert_eq!(exit["stdout_format"], "text");
}

#[test]
fn json_mode_keeps_streaming_past_a_line_that_is_not_utf8() {
    // A single stray byte -- a latin-1 filename in a build log, a progress
    // spinner -- must not end the stream. Reading with `lines()` would return
    // Err here and every later line would be dropped while the closing envelope
    // still reported success.
    let world = World::new().podman_reply_bytes("run", b"first\ntw\xffo\nthird\n", 0);
    let out = world.run(&["--json", "--", "build"]);

    let lines: Vec<serde_json::Value> = out
        .stdout
        .lines()
        .map(|l| serde_json::from_str(l).expect("each stdout line is one JSON object"))
        .collect();

    let outputs: Vec<&str> = lines
        .iter()
        .filter(|v| v["type"] == "output")
        .map(|v| v["line"].as_str().unwrap())
        .collect();
    assert_eq!(outputs.len(), 3, "no line may be dropped: {:?}", outputs);
    assert_eq!(outputs[0], "first");
    assert_eq!(outputs[2], "third");
    // The undecodable byte itself is replaced, not the line it sat in.
    assert!(
        outputs[1].starts_with("tw") && outputs[1].ends_with('o'),
        "unexpected lossy line: {:?}",
        outputs[1]
    );
}

#[test]
fn json_mode_on_a_plain_command_omits_tty_and_does_not_require_an_agent() {
    let out = World::new().run(&["--json", "--", "echo", "hi"]);

    assert_eq!(out.code, Some(0));
    let run = out.run_call();
    assert!(!run.has("--tty"), "json mode must omit --tty");
}

#[test]
fn json_mode_on_a_plain_command_reports_a_nonzero_exit_in_the_summary() {
    let world = World::new().podman_reply("run", "", 7);
    let out = world.run(&["--json", "--", "false"]);

    assert_eq!(out.code, Some(7));
    let exit_lines: Vec<serde_json::Value> = out
        .stdout
        .lines()
        .map(|l| serde_json::from_str(l).expect("each stdout line is one JSON object"))
        .filter(|v: &serde_json::Value| v["type"] == "exit")
        .collect();
    assert_eq!(exit_lines.len(), 1);
    assert_eq!(exit_lines[0]["status"], 7);
}

#[test]
fn pi_default_agent_mounts_are_bound() {
    let out = World::new().run(&["pi"]);
    let run = out.run_call();

    assert!(run.mount_to("/home/user/.pi").is_some());
    assert!(run.mount_to("/home/user/.local/share/pi").is_some());
}

#[test]
fn command_after_double_dash_is_not_intercepted_by_ctl() {
    let out = World::new().run(&["--", "make", "purge"]);
    assert!(
        out.reached_podman_run(),
        "container was not launched; stdout: {}\nstderr: {}",
        out.stdout,
        out.stderr
    );
    let run = out.run_call();
    assert_eq!(run.command(), vec!["make", "purge"]);

    let out_git = World::new().run(&["--", "git", "log"]);
    assert!(out_git.reached_podman_run());
    assert_eq!(out_git.run_call().command(), vec!["git", "log"]);

    let out_status = World::new().run(&["--", "echo", "status"]);
    assert!(out_status.reached_podman_run());
    assert_eq!(out_status.run_call().command(), vec!["echo", "status"]);

    let out_agent = World::new().run(&["opencode", "--", "make", "purge"]);
    assert!(out_agent.reached_podman_run());
    assert_eq!(out_agent.run_call().command(), vec!["make", "purge"]);
}

#[test]
fn flags_with_values_matching_subcommands_are_not_intercepted_by_ctl() {
    let out = World::new().run(&["--name", "list", "opencode"]);
    assert!(out.reached_podman_run());
    let run = out.run_call();
    assert_eq!(run.value_of("--name"), Some("agent-sandbox-ws-list"));

    let out_env = World::new().run(&["-e", "ACTION=purge", "opencode"]);
    assert!(out_env.reached_podman_run());
    assert_eq!(out_env.run_call().env_value("ACTION"), Some("purge"));

    let out_ctl = World::new().run(&["--name", "ctl", "opencode"]);
    assert!(out_ctl.reached_podman_run(), "container was not launched: stdout: {}\nstderr: {}", out_ctl.stdout, out_ctl.stderr);
    assert_eq!(out_ctl.run_call().value_of("--name"), Some("agent-sandbox-ws-ctl"));
}

#[test]
fn ctl_subcommands_run_without_ctl_prefix() {
    for cmd in [
        "list", "status", "policy", "proxy", "logs", "log", "mount", "mounts",
        "purge", "tui", "relay", "net", "browser",
    ] {
        let out = World::new().run(&[cmd, "--help"]);
        assert!(
            !out.reached_podman_run(),
            "subcommand '{}' unexpectedly reached podman run instead of ctl",
            cmd
        );
        assert_eq!(
            out.code,
            Some(0),
            "subcommand '{}' failed with code {:?}, stderr: {}",
            cmd,
            out.code,
            out.stderr
        );
    }
}

#[test]
fn direct_ctl_list_runs_ctl() {
    let out = World::new().run(&["list"]);
    assert!(!out.reached_podman_run(), "direct list reached podman run");
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
}

#[test]
fn direct_ctl_proxy_runs_ctl_policy() {
    let out = World::new().run(&["proxy", "--help"]);
    assert!(!out.reached_podman_run(), "direct proxy reached podman run");
    assert_eq!(out.code, Some(0), "stderr: {}", out.stderr);
}

#[test]
fn agent_name_takes_precedence_over_subcommand_shortcut() {
    let out = World::new()
        .env("AGENT_SANDBOX_AGENT_SPECS", "list\t[\"list_agent\"]\t[]\t[]")
        .run(&["list"]);
    assert!(out.reached_podman_run(), "agent was not launched: stderr: {}", out.stderr);
    assert_eq!(out.run_call().command(), vec!["list_agent"]);

    let out_ctl = World::new()
        .env("AGENT_SANDBOX_AGENT_SPECS", "list\t[\"list_agent\"]\t[]\t[]")
        .run(&["ctl", "list"]);
    assert!(!out_ctl.reached_podman_run(), "ctl list reached podman run");
    assert_eq!(out_ctl.code, Some(0));
}




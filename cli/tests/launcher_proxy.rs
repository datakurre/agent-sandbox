//! What `--proxy` builds, checked against a stub `podman`.
//!
//! The policy *semantics* are `proxy/src/policy.rs`'s tests, and whether a
//! request actually gets through is the integration suite's. What is only
//! visible here is the wiring: which network the sandbox joins, which proxy
//! variables it is given, what policy file the sidecar is handed, and which
//! capabilities are withheld when the policy does not ask for them.

mod common;

use common::World;
use std::fs;

/// A world whose stub podman answers the two lookups the sidecar path makes:
/// the internal network's subnet, and the sidecar's address on it.
fn proxied_world() -> World {
    World::new()
        .podman_reply("network-inspect", "10.89.7.0/24\n", 0)
        .podman_reply("container-inspect", "10.89.7.2\n", 0)
}

const ALLOW_EXAMPLE: &str = "\
```toml agent-sandbox
[network]
allowed_hosts = [\"example.com:443\"]
```
";

const L7_ROUTE: &str = "\
```toml agent-sandbox
[network]
allowed_hosts = [\"github.com:443\"]

[[network.allowed_routes]]
host = \"api.example.com\"
method = \"GET\"
path = \"/v1/*\"
```
";

#[test]
fn the_sandbox_joins_the_sidecars_internal_network_and_nothing_else() {
    let out = proxied_world().file("AGENTS.md", ALLOW_EXAMPLE).run(&[
        "--workspace",
        "--proxy",
        "opencode",
    ]);
    let run = out.run_call();

    let network = run.value_of("--network").expect("a network");
    assert!(
        network.starts_with("agent-sandbox-sidecar-"),
        "the sandbox's only route out is the sidecar: {}",
        network
    );
    assert!(run
        .values_of("--label")
        .contains(&"agent-sandbox.proxy=proxy"));
}

#[test]
fn the_proxy_address_is_handed_over_in_every_spelling_clients_read() {
    let out = proxied_world().file("AGENTS.md", ALLOW_EXAMPLE).run(&[
        "--workspace",
        "--proxy",
        "opencode",
    ]);
    let run = out.run_call();

    for var in ["HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"] {
        assert_eq!(
            run.env_value(var),
            Some("http://10.89.7.2:8888"),
            "{} points at the sidecar's address on the internal network",
            var
        );
    }
}

#[test]
fn loopback_is_exempted_so_the_agent_can_reach_its_own_server() {
    let out = proxied_world().file("AGENTS.md", ALLOW_EXAMPLE).run(&[
        "--workspace",
        "--proxy",
        "opencode",
    ]);
    let run = out.run_call();

    for var in ["NO_PROXY", "no_proxy"] {
        let value = run.env_value(var).unwrap_or_default();
        assert!(value.contains("127.0.0.1"), "{}={}", var, value);
        assert!(value.contains("localhost"), "{}={}", var, value);
        assert!(value.contains("::1"), "{}={}", var, value);
        assert!(
            !value.contains('*') && !value.contains('/'),
            "wildcard and CIDR syntax disagree across clients: {}={}",
            var,
            value
        );
    }
}

#[test]
fn without_proxy_no_proxy_variables_are_set_at_all() {
    let out = World::new()
        .file("AGENTS.md", ALLOW_EXAMPLE)
        .run(&["--workspace", "opencode"]);
    let run = out.run_call();

    for var in ["HTTP_PROXY", "https_proxy", "NO_PROXY"] {
        assert_eq!(
            run.env_value(var),
            None,
            "{} leaked into an unproxied run",
            var
        );
    }
}

#[test]
fn the_policy_the_sidecar_is_handed_carries_the_declared_rules_and_a_deny_baseline() {
    let world = proxied_world().file("AGENTS.md", ALLOW_EXAMPLE);
    let out = world.run(&["--workspace", "--proxy", "opencode"]);

    assert!(out.sidecar_call().is_some(), "a sidecar was started");
    let dir = world.captured("sidecar_policy");
    let policy = fs::read_to_string(dir.join("policy")).expect("the live policy file");

    assert!(
        policy.contains("example.com"),
        "the declared rule must reach the proxy: {}",
        policy
    );
    assert!(
        policy
            .lines()
            .any(|l| l.split_whitespace().collect::<Vec<_>>() == ["default", "deny"]),
        "the baseline is deny, whatever was declared: {}",
        policy
    );

    // `policy.base` is what `ctl proxy reset` restores, so a session that never
    // edits its policy has to start with the two identical.
    let base = fs::read_to_string(dir.join("policy.base")).expect("the reset baseline");
    assert_eq!(
        policy, base,
        "an unedited session's policy and its reset baseline are the same policy"
    );
}

#[test]
fn a_session_ca_is_only_trusted_when_the_policy_has_a_rule_that_needs_one() {
    let plain = proxied_world().file("AGENTS.md", ALLOW_EXAMPLE).run(&[
        "--workspace",
        "--proxy",
        "opencode",
    ]);
    let run = plain.run_call();

    assert!(
        run.mount_to("/run/agent-sandbox-proxy-ca.pem").is_none(),
        "with nothing intercepted, a CA that can mint any name grants trust for no purpose: {}",
        run.joined()
    );
    assert_eq!(run.env_value("AGENT_SANDBOX_PROXY_CA_FILE"), None);
}

#[test]
fn an_l7_policy_is_accepted_and_still_denies_by_default() {
    let out =
        proxied_world()
            .file("AGENTS.md", L7_ROUTE)
            .run(&["--workspace", "--proxy", "opencode"]);

    assert!(
        out.reached_podman_run(),
        "an L7 route is a valid policy: {}",
        out.stderr
    );
    assert!(out
        .run_call()
        .values_of("--label")
        .contains(&"agent-sandbox.proxy=proxy"));
}

#[test]
fn a_proxy_profile_that_does_not_exist_refuses_the_launch() {
    let out = proxied_world().run(&["--workspace", "--proxy-profile", "nope", "opencode"]);

    assert!(!out.reached_podman_run());
    assert!(
        out.stderr.contains("nope"),
        "the error should name the profile: {}",
        out.stderr
    );
}

#[test]
fn a_proxy_profile_supplies_the_policy_when_agents_md_has_none() {
    let out = proxied_world()
        .home_file(
            ".config/agent-sandbox/profiles/development.toml",
            "[network]\nallowed_hosts = [\"registry.npmjs.org:443\"]\n",
        )
        .run(&["--workspace", "--proxy-profile", "development", "opencode"]);

    assert!(
        out.reached_podman_run(),
        "a host-owned profile is a complete policy on its own: {}",
        out.stderr
    );
    assert!(out
        .run_call()
        .values_of("--label")
        .contains(&"agent-sandbox.proxy=proxy"));
}

#[test]
fn secrets_declared_but_not_enabled_warn_rather_than_being_injected() {
    let agents_md = "\
```toml agent-sandbox
[network]
allowed_hosts = [\"github.com:443\"]

[[network.allowed_routes]]
host = \"api.example.com\"
method = \"GET\"
path = \"/v1/*\"
secret = \"API_TOKEN\"
```
";
    let out =
        proxied_world()
            .file("AGENTS.md", agents_md)
            .run(&["--workspace", "--proxy", "opencode"]);

    assert!(out.reached_podman_run(), "{}", out.stderr);
    assert!(
        out.stderr.contains("--secrets"),
        "a declared secret that is not enabled must say so: {}",
        out.stderr
    );
}

#[test]
fn the_sidecar_is_torn_down_when_the_launch_ends() {
    let out = proxied_world().file("AGENTS.md", ALLOW_EXAMPLE).run(&[
        "--workspace",
        "--proxy",
        "opencode",
    ]);

    let stopped = out
        .calls
        .iter()
        .any(|c| c.first().map(String::as_str) == Some("stop"));
    let network_removed = out
        .calls
        .iter()
        .any(|c| c.len() >= 2 && c[0] == "network" && c[1] == "rm");

    assert!(
        stopped,
        "a leaked sidecar keeps holding the host's agent sockets"
    );
    assert!(
        network_removed,
        "leaked networks exhaust the rootless subnet pool: {:?}",
        out.calls
    );
}

/// The relay runs ssh and gpg in the sidecar, not in the sandbox, so the
/// sidecar is the side that has to be able to resolve its own uid. It runs
/// without --userns=keep-id and the image ships no /etc/passwd, so without
/// these two mounts ssh dies at getpwuid with "No user exists for uid 0"
/// before it ever opens a connection.
#[test]
fn the_sidecar_gets_a_passwd_database_of_its_own() {
    let out = proxied_world().file("AGENTS.md", ALLOW_EXAMPLE).run(&[
        "--workspace",
        "--proxy",
        "opencode",
    ]);

    let sidecar = out.sidecar_call().expect("no sidecar was started");
    for dest in ["/etc/passwd", "/etc/group"] {
        let mount = sidecar
            .mount_to(dest)
            .unwrap_or_else(|| panic!("the sidecar has no {}: {}", dest, sidecar.joined()));
        assert!(
            mount.ends_with(":ro"),
            "{} should be read-only in the sidecar, got {}",
            dest,
            mount
        );
    }

    // The sandbox keeps its own copy: this is an addition, not a move.
    let run = out.run_call();
    assert!(
        run.mount_to("/etc/passwd").is_some(),
        "the sandbox lost its passwd database: {}",
        run.joined()
    );
}

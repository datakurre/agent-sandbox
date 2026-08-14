# AGENTS.md Configuration Guide

The `agent-sandbox` launcher supports declarative configuration defined directly within the project's `AGENTS.md` file. The configuration allows you to expose ports, define volume mounts, and set fine-grained network firewall policies.

Configurations must be written in TOML and placed inside a fenced code block tagged with `agent-sandbox`:

```toml agent-sandbox
# Configuration goes here
```

The launcher parses this configuration when starting the sandbox environment.

## Supported Tables

The following top-level tables are supported:

### 1. `[ports]`

The `[ports]` table is used to declare container ports that should be published to the host, equivalent to Podman's `--publish` (`-p`) flag.

Each entry is a key-value pair where the key is the mapping name. The value can either be an integer (the container port) or a table with the following fields:

- **`container`** (required): The port inside the container (1-65535).
- **`host`** (optional): The port on the host to bind to. Defaults to the `container` port. If set to `0`, the launcher will dynamically allocate a free host port.
- **`bind`** (optional): The IP address on the host to bind to, or `"localhost"`. Defaults to `127.0.0.1`. Note: Binding to an interface other than loopback requires the launcher to be run with `--ports-any-interface`.
- **`protocol`** (optional): The protocol to use, either `"tcp"` or `"udp"`. Defaults to `"tcp"`.

#### Examples

```toml agent-sandbox
[ports]
# Simple mapping: host 3000 -> container 3000 (binds to 127.0.0.1)
web = 3000

# Advanced mappings using tables
api = { container = 8080, host = 18080 }
db  = { container = 5432, host = 0 } # 0 means allocate a free host port dynamically
dns = { container = 53, protocol = "udp", bind = "0.0.0.0" }
```

### 2. `[mounts]`

The `[mounts]` table allows you to bind mount paths from the host into the sandbox container. 

Each key represents the source path (which can be absolute or relative to the workspace directory). The value can be a string representing the destination path inside the container, or a table with additional options.

Fields when using a table:
- **`destination`** (required): The absolute path inside the container.
- **`options`** (optional): A string or list of strings representing mount options (e.g., `"ro"`, `"rw"`, `"Z"`).

#### Examples

```toml agent-sandbox
[mounts]
# Simple source -> destination mapping
"data" = "/workspace/data"

# Advanced mapping with options
"cache" = { destination = "/tmp/cache", options = "ro" }
"logs" = { destination = "/var/log/app", options = ["rw", "Z"] }
```

### 3. `[network]`

The `[network]` table configures the egress proxy's firewall policy. The sandbox is **deny-by-default**, meaning all traffic is blocked unless explicitly allowed.

- **`allow`** (optional): A list of IP addresses, CIDR blocks, or domains along with their port to allow (e.g., `"github.com:443"`, `"10.0.0.0/8:80"`). Wildcard domains (e.g., `"*.github.com:443"`) are supported. To allow all traffic (wildcard allow), you can use `"*"` or `"*:port"`.

An `allow` entry on port `22` does double duty: it is also what authorizes the
SSH/GPG relay for that host. Under `--proxy` the host agent sockets are held by
the proxy sidecar rather than mounted into the sandbox, and the relay refuses
every request until at least one such entry exists — so `"github.com:22"` is
what makes `git push` and commit signing work in a proxied sandbox. See
[Usage](usage.md#git-integration-details).

#### L7 HTTP Rules (`[[network.rules]]`)

For finer-grained HTTP proxy control and secret injection, you can specify an array of tables under `[[network.rules]]`.

- **`host`** (required): The target host and port to match (e.g., `"api.github.com:443"`).
- **`method`** (required): The HTTP method (e.g., `"GET"`, `"POST"`, or `"*"`) in uppercase.
- **`path`** (required): The path prefix to match (must start with `/`).
- **`secret`** (optional): The name of a secret to inject into requests matching this rule.
- **`header`** (optional): The HTTP header to inject the secret into (e.g., `"Authorization"`).
- **`prefix`** (optional): An optional prefix for the secret value (e.g., `"Bearer "` ).

#### Examples

```toml agent-sandbox
[network]
allow = [
    "github.com:443",
    "*.pypi.org:443",
    "10.0.0.0/8:80"
]

# Allow GET requests to specific GitHub API endpoints and inject a secret token
[[network.rules]]
host = "api.github.com:443"
method = "GET"
path = "/user/repos"
secret = "GITHUB_TOKEN"
header = "Authorization"
prefix = "Bearer "

[[network.rules]]
host = "registry.npmjs.org:443"
method = "*"
path = "/"
```

#### Secrets

A rule's `secret` names a secret, never its value. `AGENTS.md` is part of the
repository and is therefore treated as untrusted: the launcher will only inject
a secret that you have also authorized host-side, in
`~/.config/agent-sandbox/secrets.toml`, using the same fields:

```toml
# ~/.config/agent-sandbox/secrets.toml
[[network.rules]]
host = "api.github.com"
secret = "GITHUB_TOKEN"
header = "Authorization"
prefix = "Bearer "
```

With `--secrets`, values are resolved on the host with
[`secretspec`](https://secretspec.dev) (from the workspace's `secretspec.toml`)
and handed to the proxy sidecar alone; they never enter the sandbox's
environment. A rule that `AGENTS.md` requests but the host config does not
authorize refuses the launch rather than silently injecting nothing. The proxy
terminates TLS for hosts carrying a rule, so the sandbox trusts a per-session CA
that exists only for the lifetime of that sandbox.

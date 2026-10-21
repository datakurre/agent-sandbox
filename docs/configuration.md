# Configuration

`AGENTS.md` in the root of a project can contain a fenced code block tagged `agent-sandbox` with TOML configuration. The launcher reads it when starting the sandbox and uses it to expose ports, bind host paths, and enforce a network firewall policy. Network policies can also be kept as reusable host-owned policy files.

Configurations must be written in TOML and placed inside a fenced code block tagged with `agent-sandbox`:

````markdown
```toml agent-sandbox
# Configuration goes here
```
````

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

````markdown
```toml agent-sandbox
[ports]
# Simple mapping: host 3000 -> container 3000 (binds to 127.0.0.1)
web = 3000

# Advanced mappings using tables
api = { container = 8080, host = 18080 }
db  = { container = 5432, host = 0 } # 0 means allocate a free host port dynamically
dns = { container = 53, protocol = "udp", bind = "0.0.0.0" }
```
````

#### Who reads this block

The launcher publishes these ports only when it is given `--ports`; without it
the declaration is inert.

[`agent-sandbox browser`](browser.md)
reads the same block whether or not `--ports` was passed, and allows each
loopback-bound entry — as `127.0.0.1:<host>` and as `localhost:<host>` — in the
browser's own deny-by-default policy, so the app under test loads without
naming its port a second time under `[network]`. A `host = 0` entry is
allocated at launch and cannot be allowed ahead of time; give it a fixed host
port if a browser needs to reach it.

### 2. `[mounts]`

The `[mounts]` table allows you to bind mount paths from the host into the sandbox container. 

Each key represents the source path on the host: absolute, `~`-prefixed (your
home directory), or relative to the workspace directory, with `.` naming the
workspace itself. The value can be a string representing the destination path
inside the container, or a table with additional options. A relative destination
is placed under `/workspace` (`"data"` mounts at `/workspace/data`, and `"."` at
`/workspace` itself); an absolute one is used as written.

The block is honored only with `--mounts`. A source inside the workspace — the
repository's own tree — is mounted as declared. A source anywhere else —
`~/.cache/pip`, `/etc`, or a workspace path that only leads outside through a
symlink — is the repository reaching into your host, so it is mounted only once
`~/.config/agent-sandbox/trusted.toml` carries the same entry, with the same
destination and options:

```toml
# ~/.config/agent-sandbox/trusted.toml
[mounts]
"~/.cache/pip" = { destination = "/home/user/.cache/pip", options = "ro" }
```

Without it the launch refuses, naming the sources and printing the block to
paste, with each source written as the real path it resolves to. A trusted source
must be absolute or start with `~`; sources are compared with symlinks resolved,
so `~/x` and `/home/you/x` are the same entry, and options are compared as a set.
A read-only authorization does not cover a read-write mount, nor one at another
destination. A trusted path that lies inside the workspace being launched
authorizes nothing, since the repository controls the symlinks along it. A source
that does not exist refuses the launch too, as podman would. See
[Trust model](trust-model.md).

Fields when using a table:

- **`destination`** (required): The path inside the container, absolute or relative to `/workspace` as above.
- **`options`** (optional): A string or list of strings representing mount options (e.g., `"ro"`, `"rw"`, `"Z"`).

#### Examples

````markdown
```toml agent-sandbox
[mounts]
# Simple source -> destination mapping
"data" = "/workspace/data"

# Advanced mapping with options
"cache" = { destination = "/tmp/cache", options = "ro" }
"logs" = { destination = "/var/log/app", options = ["rw", "Z"] }
```
````

### 3. `[network]`

The `[network]` table configures the egress proxy's firewall policy. The sandbox is **deny-by-default**, meaning all traffic is blocked unless explicitly allowed.

- **`allowed_hosts`** (optional): A list of IP addresses, CIDR blocks, or domains, each with the port it may be reached on (e.g., `"github.com:443"`, `"10.0.0.0/8:80"`). Wildcard domains (e.g., `"*.github.com:443"`) are supported. To allow all traffic (wildcard allow), you can use `"*"` or `"*:port"`.

  An entry may omit the port (`"github.com"`), in which case the built-in
  default ports **80, 443 and 22** apply to it — not every port. Write the
  port explicitly for anything else; a rule that carries one is matched on
  that port alone.

  The port may also be a range or a comma-separated list of ports and ranges:
  `"github.com:22,443"` and `"internal.example.com:8000-8100,9000"` are both
  one entry. Writing them as separate entries works identically — the proxy
  unions the ports of every rule sharing a pattern — so the list is a
  convenience, not a different semantics.

  An entry can also carry an HTTP method list, a path, or both, which makes it
  a route rather than a plain allow — see [Short-form routes](#short-form-routes).

An `allowed_hosts` entry covering port `22` is what authorizes the SSH relay for that
host. Under `--proxy` the host agent sockets are held by the proxy sidecar
rather than mounted into the sandbox, and the relay refuses every SSH request
until a matching entry exists — so `"github.com:22"` is what makes `git push`
work in a proxied sandbox. Commit signing is separate: it needs no network
declaration at all, since GPG has no destination of its own — `--gpg` alone is
sufficient, in a proxied sandbox exactly as in an unproxied one. See
[Usage](usage.md#git-integration-details).

#### L7 HTTP Rules (`[[network.allowed_routes]]`)

For finer-grained HTTP proxy control and secret injection, you can specify an array of tables under `[[network.allowed_routes]]`.

- **`host`** (required): The target host and port to match (e.g., `"api.github.com:443"`).
- **`method`** (required): The HTTP method (e.g., `"GET"`, `"POST"`, or `"*"`) in uppercase.
- **`path`** (optional): The path pattern to match (must start with `/`). `*` matches a single
  segment, `**` matches several. Omitted or empty, it defaults to `"/**"`, every path, so a
  rule with only `host` and `method` narrows a host by method alone.
- **`secret`** (optional): The name of a secret to inject into requests matching **this rule**.
- **`header`** (optional): The HTTP header to inject the secret into (e.g., `"Authorization"`).
- **`prefix`** (optional): An optional prefix for the secret value (e.g., `"Bearer "` ).

A host may carry several rules, and `secret` binds to the rule it is written on —
not to the host. Only requests matching that rule's method and path receive the
header; every other rule on the same host is proxied without it. Matching runs
against the fully percent-decoded path — a percent-encoded slash (`%2F`) decodes
like any other escape, so a path segment that legitimately contains one (a scoped
npm package name such as `/@scope%2fname`, a GitLab-style project id such as
`/api/v4/projects/group%2Fproject`) matches normally. A request whose decoded path
is still ambiguous — a `.` or `..` segment, an empty `//` segment, a backslash
(literal or `%5C`), or a control byte — is refused outright with `400 Bad Request`
rather than normalised, so it cannot be matched against one route and forwarded to
another.

A rule restricts a whole domain, not one port. The proxy matches a route by its
domain pattern alone — the port in `host` reaches the policy as an ordinary
allow entry, not as part of the route — so once any rule matches a host, the
proxy holds all its traffic to that host to its rules, whichever entry let it
through: HTTPS on port 443 and plain HTTP must match a rule's method and path,
and a `CONNECT` tunnel to any other port (`:8443`, say) is refused outright,
because only port 443 is intercepted. Plain HTTP to a host carrying a `secret`
rule is refused before any matching, since a secret is never sent in cleartext.
A wildcard rule reaches as far as its pattern: a rule on `*.example.com` also
restricts `example.com` and `api.example.com`, even where `allowed_hosts` lists
them on their own. SSH is the exception: the relay that carries `git push` under
`--proxy` is authorized by the port-22 entry alone and never consults routes.

#### Examples

````markdown
```toml agent-sandbox
[network]
allowed_hosts = [
    "github.com:443",
    "*.pypi.org:443",
    "10.0.0.0/8:80"
]

# Allow GET requests to specific GitHub API endpoints and inject a secret token
[[network.allowed_routes]]
host = "api.github.com:443"
method = "GET"
path = "/user/repos"
secret = "GITHUB_TOKEN"
header = "Authorization"
prefix = "Bearer "

# Read-only access to the npm registry: any path, GET only
[[network.allowed_routes]]
host = "registry.npmjs.org:443"
method = "GET"

# OpenCode Zen: Programmatic agent inference injection
[[network.allowed_routes]]
host = "opencode.ai:443"
method = "POST"
path = "/zen/v1/*"
secret = "OPENCODE_API_KEY"
header = "Authorization"
prefix = "Bearer "
```
````

#### Short-form routes

A route without a secret can also be written as one `allowed_hosts` entry, with
a method list before the domain, a path after it, or both:

````markdown
```toml agent-sandbox
[network]
allowed_hosts = [
    "github.com:443",                         # a plain allow entry
    "POST *.example.com:443/foo/*",           # one route
    "GET,POST *.example.com:80,443/foo/**",   # one route per method
    "GET registry.npmjs.org:443",             # GET only, every path
    "api.example.net:8443/v2/**",             # every method, under /v2/
]
```
````

The form is `METHODS DOMAIN[:PORTS][/PATH]`: methods separated by commas alone,
then whitespace, then the domain. An entry is a route as soon as it has a method
list or a path; one with neither is a plain allow entry, and so is a CIDR block
such as `"10.0.0.0/8:80"`, whose `/` is a prefix length. A missing path means
`"/**"` and a missing method list `"*"`, the defaults of a table, and each entry
compiles to exactly the `[[network.allowed_routes]]` tables it stands for:
`"GET,POST *.example.com:80,443/foo/**"` is two tables, one per method, each
with `host = "*.example.com:80,443"` and `path = "/foo/**"`. Everything above
about routes holds for them — a route restricts its whole domain.

The short form only narrows. A route that injects a secret needs a table, since
`secret`, `header` and `prefix` have nowhere to go, and so does a route on an IP
address: a short-form route names a domain, not an IP, a CIDR block or `*`. Its
ports must not cover 22 either, since a route is HTTP; write `"host:22"` as an
entry of its own for SSH. `agent-sandbox ctl policy export` always writes routes
back as tables.

#### The trusted config

`AGENTS.md` is part of the repository and is therefore treated as untrusted: it
may *name* a host, but it may not decide what is trusted about that host.
Anything in that category is authorized in a file only you write,
`~/.config/agent-sandbox/trusted.toml` (or under `$XDG_CONFIG_HOME`). Profile
rules go through the same check.

Three things live under that rule, and all work the same way — the launcher
prints the exact block to paste, and refuses the launch rather than proceeding
unauthorized:

| Declared in `AGENTS.md` | Authorized in `trusted.toml` |
| --- | --- |
| `[[network.allowed_routes]]` with a `secret` | the identical `[[network.allowed_routes]]` block |
| an `allowed_hosts` entry covering port 22 | a `[[network.known_hosts]]` entry for that host |
| a `[mounts]` entry whose source is outside the workspace | the identical `[mounts]` entry |

#### Secrets

A rule's `secret` names a secret, never its value. The launcher will only
inject a secret you have also authorized host-side.

**Copy the block verbatim.** Authorization matches on every field — `host`
(including its port), `method`, `path`, `secret`, `header` and `prefix` — so
the host-side entry is the `AGENTS.md` rule with nothing changed:

```toml
# ~/.config/agent-sandbox/trusted.toml
[[network.allowed_routes]]
host = "api.github.com:443"
method = "GET"
path = "/user/repos"
secret = "GITHUB_TOKEN"
header = "Authorization"
prefix = "Bearer "
```

`method` is required on both sides, as it is everywhere a route is written.
Earlier versions read a `trusted.toml` route without one as `method = "GET"`;
such an entry now refuses the launch, naming it, and adding `method = "GET"`
keeps its old meaning. An omitted optional field takes its default on both sides — `path` defaults to
`"/**"` and `header` to `"Authorization"` — and the results are then compared
exactly, so `path = "/"` in `trusted.toml` does not authorize
a rule that leaves `path` out. Because the `path` default is every path, a
secret rule without one is injected into every request with its method on that
host. An entry without the port authorizes nothing for a rule that has one.

A secret rule's `host` must name port `443` or no port: secrets are injected
only into HTTPS that the proxy intercepts, which is port 443, and the launcher
refuses any other port rather than authorize it and inject somewhere else. A
`*.example.com` host also covers `example.com` itself, for secrets as for every
other rule.

The authorization is what scopes the injection. The secret reaches the proxy
bound to that host, method and path, and is injected only into requests matching
it — so a second `[[network.allowed_routes]]` entry in `AGENTS.md`, on the same host and
without a `secret`, grants plain access and nothing more. You can authorize
several routes on one host; where two of them could match the same request, the
more specific wins (longest domain pattern, then the longest literal path prefix
before any `*` — so the default `"/**"` loses to every narrower path — then an
exact method over `*`).

With `--secrets`, values are resolved on the host with
[`secretspec`](https://secretspec.dev) (from the workspace's `secretspec.toml`)
and handed to the proxy sidecar alone; they never enter the sandbox's
environment. A rule that the selected network sources request but the host config does not
authorize refuses the launch rather than silently injecting nothing, and prints
the exact block to paste. The proxy terminates TLS for hosts carrying a rule, so
the sandbox trusts a per-session CA that exists only for the lifetime of that
sandbox.

### Pi: two independent ways to hold a credential

**Pi** supports two unrelated ways to authenticate a model provider, and it is
easy to mix them up:

1. **Pi's own `/login`**, which writes a real credential into Pi's persisted
   state (`.pi`, mounted across launches like any other agent's login — see
   `--agent-mounts` in [Usage](usage.md)). The real key lives inside the
   sandbox and travels with the container's normal home-state mount — no
   `--secrets`/`--proxy` involved. This is the simplest option when you are
   fine with the sandbox holding the key itself.
2. **Route-scoped secret injection** (this section), for when you deliberately
   do *not* want the real key inside the sandbox at all. Pi is given a
   placeholder credential pointed at the real endpoint; the proxy swaps in the
   real `Authorization` header only on requests matching an authorized route.

The two coexist without conflict — they configure different provider entries,
so a real `/login` credential for one provider and a placeholder-keyed,
proxy-backed provider for another can both be present at once.

Option 2 splits further, by where the placeholder credential lives, which
follows from Pi's own credential resolution order (CLI flag, then
`~/.pi/agent/auth.json`, then environment variable, then a `models.json`
provider's inline `apiKey`):

- **A provider Pi ships natively** — `opencode` (OpenCode Zen), `opencode-go`,
  and most others in Pi's [provider docs](https://github.com/earendil-works/pi-mono/blob/main/packages/ai/src/env-api-keys.ts)
  — reads its key from an environment variable (`OPENCODE_API_KEY` for both
  OpenCode providers). No `models.json` entry is needed at all: run with
  `--proxy --secrets --provider opencode --model <id> -e OPENCODE_API_KEY=placeholder`.
  Pi only checks that the variable is non-empty before it will build the
  request; the byte value never leaves the sandbox because the matching
  `[[network.allowed_routes]]` rule (the OpenCode Zen example above) has the
  proxy replace the header in flight. Pi's own built-in catalog for the
  provider (refreshed live, cached in `~/.pi/agent/models-store.json`) already
  lists every callable model, so `--model` takes any id from there.
- **A provider Pi does not ship** — a self-hosted endpoint, or one Pi has no
  native entry for — has no environment variable to hook, so define it as a
  custom provider instead, with a placeholder `apiKey` and the real `baseUrl`,
  in `.pi/models.json` (or `~/.pi/agent/models.json` globally):

  ```json
  {
    "providers": {
      "my-proxied-provider": {
        "baseUrl": "https://example.com/v1",
        "api": "openai-completions",
        "apiKey": "placeholder",
        "models": [
          { "id": "my-model", "name": "My Model" }
        ]
      }
    }
  }
  ```
  Set `"defaultProvider"`/`"defaultModel"` in `.pi/settings.json` to match, or
  pass `--provider my-proxied-provider --model my-model` on the command line,
  and run with `--proxy --secrets`. A project-local `.pi/models.json` always
  takes precedence over the global one.

#### SSH host keys

An `allowed_hosts` entry covering port 22 authorizes SSH to that host — it is
what makes `git push` work in a proxied sandbox. Which host key is trusted for
it is a separate decision, and a host-side one:

```toml
# ~/.config/agent-sandbox/trusted.toml
[[network.known_hosts]]
host = "github.com:22"
key = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl"
```

`key` is a `known_hosts` key — the type and the base64, without the leading
host, which comes from `host`. Repeat the block for a host's other key types.
A fingerprint is not a key: use one to *verify* what you paste, not in its
place.

Declare `"github.com:22"` with no matching entry and the launch refuses, naming
the host and printing the block to add. For the common forges the key is filled
in for you; for anything else, get it with `ssh-keyscan` **on the host** and
check the result against a fingerprint you already trust — `ssh-keyscan` asks
the server who it is, so it cannot tell you the answer is wrong.

The port matters here as it does everywhere else. An entry for
`"git.example.com:2222"` is what `ssh -p 2222` needs, and it is not
authorization for a connection to port 22.

Under `--proxy` the authorized set is the whole trusted set: the keys are bound
into the sandbox and the sidecar at launch, and nothing running can add to them.
`agent-sandbox ctl policy allow HOST:22` and the TUI's `a` therefore say so when
they authorize a host you have no key for — the rule takes effect, and SSH to it
will fail host-key verification until you add one and relaunch.

#### Rules the launcher refuses

`[network]` is validated before the sandbox starts; an invalid block refuses the
launch rather than starting with a policy that allows more than you wrote.
Besides malformed values, these combinations are rejected, comparing host names
without regard to case, as the proxy does:

- an unknown key under `[network]` (only `allowed_hosts` and `allowed_routes` exist) or an unknown
  field on a rule;
- a duplicate entry in `allowed_hosts`, including a
  [short-form route](#short-form-routes) that repeats the method, host and path
  of another one or of a `[[network.allowed_routes]]` table;
- a host allowed outright in `allowed_hosts` that also carries a `[[network.allowed_routes]]`
  entry *without* a secret, or a short-form route — the route holds the host to
  its rules on every port, so the plain entry grants nothing beside it and one of
  the two is a mistake. The domain pattern decides, whatever ports either entry
  names: `"a.example:8443"` conflicts with a route on `a.example:443`, while
  `"*.a.example:443"` does not conflict with a route on `a.example`. A plain entry
  on port 22 alone is the exception, since SSH goes through the relay and never
  meets the route. The same applies to a wildcard allow (`"*"`, `"*:port"`).
  This is checked across every `agent-sandbox` block in the file, not only
  within one;
- an `allowed_hosts` entry covering port 22 for a host with no
  `[[network.known_hosts]]` entry in `trusted.toml` — SSH would be authorized to
  a host whose identity nothing has vouched for.

There is no `deny` key. The firewall is deny-by-default, and the only deny rules
a policy carries are the built-in private and loopback ranges the launcher adds
to every session. See [Trust model](trust-model.md).

## Reusable Network Policies

Policies are explicit, host-owned network policies stored under:

```text
$XDG_CONFIG_HOME/agent-sandbox/policies/<name>.toml
```

When `XDG_CONFIG_HOME` is unset, the default location is:

```text
~/.config/agent-sandbox/policies/<name>.toml
```

Policy files are plain TOML and contain only a `[network]` table. They use the
same `allowed_hosts` and `[[network.allowed_routes]]` syntax as `AGENTS.md`:

```toml
[network]
allowed_hosts = ["github.com:443", "registry.npmjs.org:443"]
```

For a sandbox launch, `--policy NAME` requires `--proxy` — passing `--policy`
without `--proxy` is refused before the sidecar starts, rather than silently
turning the proxy on. With `--proxy`, a named policy merges additively with the
workspace's `AGENTS.md` `[network]` block (if any). The option may be repeated.
Invalid or missing policies refuse the launch before the sidecar starts.

`--no-policy` clears named policies collected earlier on the command line and
skips the implicit per-agent policy, but does not disable the proxy or the
workspace's `AGENTS.md` policy. A later `--policy NAME` re-enables host-owned
policy loading, so `--policy old --no-policy --policy new` loads only `new`
and the current agent's implicit policy.

Unless `--no-policy` is given, an agent also gets its own policy implicitly:
launching with `--proxy` checks
`~/.config/agent-sandbox/policies/<agent>.toml` (the same directory, keyed by
the agent name from `agents.nix`, e.g. `claude.toml`) and merges it
automatically if it exists — no `--policy` needed. This is how an
organization-wide allow list for one agent can apply to every project that
launches it. Startup prints where policies were looked up and which files
were actually loaded.

The same policies are taken by
[`agent-sandbox browser`](browser.md)
via its own `--policy`, so one allow list can serve both a sandbox and
the browser testing it. They stay separate policies — selecting a policy for
one does not select it for the other. The browser has its own deny-by-default
proxy, so `agent-sandbox browser --policy NAME` does not need a sandbox
`--proxy` flag. Unlike the launcher, the browser always checks the current
directory's `AGENTS.md` for both `[ports]` and `[network]`; `--policy` only adds
to that.

Live rules added during a session are not written back automatically. The exit
summary prints a TOML block that can be added to `AGENTS.md` for project-specific
access or merged into a policy file for reuse.

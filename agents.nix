# An agent is a CLI command plus the home paths that persist its login state.
#
# Every launcher flag that reaches the agent is declared here per agent, as the
# argument list to splice in. An agent that does not declare a mapping does not
# support that flag: the launcher refuses the run rather than inventing a spelling
# the agent would reject or, worse, silently misread. `{}` in a mapping is where
# the user's value goes; with no `{}` it is appended, which is the common
# `--model NAME` shape.
#
# `jsonArgs` is the one entry that carries no user value: it is how an agent is
# told to speak JSON, spliced in when the launcher itself was asked for `--json`,
# so the agent's own output can go into the result envelope as JSON instead of as
# a string of escaped JSON. An agent without it is not refused -- its output is
# just text, and the envelope keeps reporting it as a string.
#
# The shape of this file is checked at build time against ./agents-schema.json.
{ pkgs }:
[
  {
    name = "opencode";
    package = pkgs.opencode;
    # No ".": the bare command is opencode's TUI, whose `[project]` positional
    # already defaults to the cwd the sandbox starts it in -- and a positional is
    # in the way of `run` below.
    command = [
      "opencode"
    ];
    # `opencode run` ("run opencode with a message"), not the TUI's `--prompt`.
    # The top-level command is the TUI: given `--prompt -` it took "-" as the
    # prompt *text* and still tried to start the interface, which without a tty
    # printed the usage banner and exited 1 -- so this agent had no working
    # programmatic mode at all. `run` takes its message from stdin when no
    # message positional is given, which is exactly what `--prompt -` asks for,
    # and it is the only form that has `--format json`.
    programmaticArgs = [
      "run"
    ];
    jsonArgs = [
      "--format"
      "json"
    ];
    modelArg = [
      "--model"
    ];
    sessionArg = [
      "--session"
    ];
    # opencode's own `--fork` is a boolean qualifying a resume, not an id-taking
    # flag: "fork the session when continuing (use with --continue or --session)".
    forkArg = [
      "--session"
      "{}"
      "--fork"
    ];
    # No provider flag: opencode selects a provider through the `provider/model`
    # form of --model, and `opencode providers` manages credentials.
    state = [
      ".local/share/opencode"
      ".config/opencode"
      ".cache/opencode"
    ];
  }
  {
    name = "claude";
    package = pkgs.claude-code;
    command = [ "claude" ];
    programmaticArgs = [
      "-p"
      "-"
    ];
    # "json (single result)"; the alternative, "stream-json", additionally
    # requires --verbose and emits the same turn as a line per event. One result
    # object per run is the closer match to what a buffered --prompt run reports.
    jsonArgs = [
      "--output-format"
      "json"
    ];
    modelArg = [
      "--model"
    ];
    # `--session-id` exists too, but it *assigns* an id to a new conversation.
    # Resuming one by id is `--resume`.
    sessionArg = [
      "--resume"
    ];
    # `--fork-session`: "When resuming, create a new session ID instead of reusing
    # the original (use with --resume or --continue)".
    forkArg = [
      "--resume"
      "{}"
      "--fork-session"
    ];
    # No provider flag: third-party backends (Bedrock/Vertex/Foundry) are selected
    # by environment and settings, not on the command line.
    state = [ ".claude" ];
    stateFiles = [ ".claude.json" ];
  }
  {
    name = "copilot";
    package = pkgs.github-copilot-cli;
    command = [ "copilot" ];
    programmaticArgs = [
      "-p"
      "-"
    ];
    # "'text' (default) or 'json' (JSONL, one JSON object per line)".
    jsonArgs = [
      "--output-format"
      "json"
    ];
    modelArg = [
      "--model"
    ];
    # "Resume an existing session or task by ID, or set the UUID for a new session".
    sessionArg = [
      "--session-id"
    ];
    # No fork flag, and no provider flag (BYOK providers are configured, not passed).
    #
    # No creditLimitArg either: `--max-ai-credits` was declared here until
    # github-copilot-cli 1.0.61, which rejects it outright ("error: unknown option
    # '--max-ai-credits'"). Budget is surfaced in-session (`/usage`, the footer)
    # rather than capped from the command line. Restore the mapping if a future
    # release brings the flag back -- the launcher flag stays, it just has no
    # agent declaring it today.
    state = [ ".copilot" ];
  }
  {
    name = "antigravity";
    package = pkgs.google-antigravity-cli;
    command = [
      "agy"
    ];
    programmaticArgs = [
      "--prompt"
      "-"
    ];
    # "Output format for print mode (text, json, stream-json)".
    jsonArgs = [
      "--output-format"
      "json"
    ];
    modelArg = [
      "--model"
    ];
    # agy calls a session a conversation: "Resume a previous conversation by ID".
    sessionArg = [
      "--conversation"
    ];
    # No fork flag, no provider flag.
    state = [
      ".local/share/antigravity-cli"
      ".config/antigravity-cli"
      ".cache/antigravity-cli"
      ".gemini/antigravity-cli"
      ".gemini/config/projects"
    ];
    stateFiles = [
      ".gemini/config/config.json"
      ".gemini/config/mcp_config.json"
    ];
  }
  {
    name = "codex";
    package = pkgs.codex;
    # As with pi, no ".": `codex [OPTIONS] [PROMPT]` takes a prompt positional, not a
    # project directory, so the "." was reaching the model as codex's first turn.
    command = [
      "codex"
    ];
    # Non-interactive codex is the `exec` subcommand, whose PROMPT argument documents
    # "-" as read-from-stdin. Plain `codex -p -` did not do this at all: codex has no
    # `-p/--print`, `-p` is `--profile <CONFIG_PROFILE_V2>`, so that spelling asked for
    # a config profile named "-" and still launched the interactive TUI.
    programmaticArgs = [
      "exec"
      "-"
    ];
    # `codex exec --json`: "Print events to stdout as JSONL".
    jsonArgs = [
      "--json"
    ];
    modelArg = [
      "--model"
    ];
    # No sessionArg: resuming is `codex exec resume <SESSION_ID> [PROMPT]`, a
    # *subcommand* that has to sit between `exec` and the prompt argument. A mapping
    # here can only splice in after the prompt args, which would put `resume` where
    # codex expects nothing, so --session is refused instead of mis-spelled. Lifting
    # this needs the prompt args themselves to become session-aware.
    # No fork flag; `--oss`/`--local-provider` are not the same thing as --provider.
    state = [
      ".codex"
    ];
  }
  {
    name = "pi";
    package = pkgs.callPackage ./pi-coding-agent.nix { };
    # No "." here: pi's usage is
    # `pi [options] [@files...] [messages...]`, so a bare positional is a *message*, not
    # the project directory. pi works from the cwd the sandbox already puts it in. Passed
    # anyway, the "." was sent to the model -- as the first interactive turn, and
    # concatenated onto the piped prompt under `--prompt -` (pi's buildInitialMessage
    # joins stdin content and the first message positional with no separator, so
    # "Summarize the repo" arrived as "Summarize the repo.").
    command = [
      "pi"
    ];
    # `-p`/`--print` is a boolean flag (process the prompt and exit), not a value-taking
    # one -- unlike opencode/antigravity's `--prompt -`, pi has no "-" stdin marker at
    # all, and passing one is a hard parse error ("Unknown option: -"). It reads stdin as
    # the prompt automatically whenever one is piped in and no message positional is
    # given -- which is why `command` above must not add one.
    programmaticArgs = [
      "-p"
    ];
    # "Output mode: text (default), json, or rpc". This lived in
    # programmaticArgs until --json grew per-agent output flags, which meant a
    # plain `--prompt` run -- one whose output a human reads -- got pi's event
    # stream too. Here it follows the launcher's own --json instead.
    jsonArgs = [
      "--mode"
      "json"
    ];
    modelArg = [
      "--model"
    ];
    sessionArg = [
      "--session"
    ];
    forkArg = [
      "--fork"
    ];
    providerArg = [
      "--provider"
    ];
    # No stateFiles/stateFileSeeds: pi ships its own built-in catalogs for
    # known providers (opencode, opencode-go, ...) and refreshes them itself,
    # cached under .pi/agent/models-store.json -- which the whole-directory
    # ".pi" mount below already covers. An earlier revision pre-seeded a
    # hand-copied OpenCode Zen catalog into a custom "opencode-zen" provider
    # here on the premise that route-scoped secret injection needed a
    # models.json-defined provider to carry its dummy key. It doesn't: pi's
    # built-in "opencode"/"opencode-go" providers already read their key from
    # $OPENCODE_API_KEY (docs/providers.md's credential resolution order),
    # so a plain `-e OPENCODE_API_KEY=<placeholder>` satisfies pi's own
    # pre-flight check and the proxy still swaps in the real header per
    # matched route -- see the Pi section in docs/configuration.md.
    state = [
      ".pi"
      ".local/share/pi"
      ".config/pi"
      ".cache/pi"
    ];
  }
  {
    name = "graph-agent";
    package = pkgs.graph-agent;
    # Bare `graph-agent` prints the usage banner; interactive launch runs the TUI.
    command = [
      "graph-agent"
      "tui"
    ];
    # No programmaticArgs: graph-agent's `run` subcommand takes a positional prompt
    # and does not read prompts from stdin (`-`), so `--prompt` is not supported.
    modelArg = [
      "--model"
    ];
    # `tui --resume <session>` reattaches to a parked session.
    sessionArg = [
      "--resume"
    ];
    # Persistent state: `.config/graph-agent` holds configuration and workflows
    # ($XDG_CONFIG_HOME), `.local/state/graph-agent` holds sessions and logs
    # ($XDG_STATE_HOME), and `.pi` holds Pi models and credentials used by Pi's
    # ModelRuntime.
    state = [
      ".config/graph-agent"
      ".local/state/graph-agent"
      ".pi"
      ".local/share/pi"
      ".config/pi"
      ".cache/pi"
    ];
  }
]

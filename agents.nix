# An agent is a CLI command plus the home paths that persist its login state.
#
# Every launcher flag that reaches the agent is declared here per agent, as the
# argument list to splice in. An agent that does not declare a mapping does not
# support that flag: the launcher refuses the run rather than inventing a spelling
# the agent would reject or, worse, silently misread. `{}` in a mapping is where
# the user's value goes; with no `{}` it is appended, which is the common
# `--model NAME` shape.
#
# The shape of this file is checked at build time against ./agents-schema.json.
{ pkgs }:
[
  {
    name = "opencode";
    package = pkgs.opencode;
    command = [
      "opencode"
      "."
    ];
    programmaticArgs = [
      "--prompt"
      "-"
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
      "."
    ];
    programmaticArgs = [
      "--prompt"
      "-"
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
    # No "." here, unlike opencode/antigravity: pi's usage is
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
      "--mode"
      "json"
      "-p"
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
    state = [
      ".pi"
      ".local/share/pi"
      ".config/pi"
      ".cache/pi"
    ];
    # Nested inside the ".pi" state dir above on purpose: state dirs are a
    # whole-directory bind mount from the host, so anything the image puts
    # under .pi is invisible the moment that mount lands, and a host that has
    # never run pi starts with nothing there.  A stateFiles entry mounts the
    # single file over the top of that directory mount, seeded once (see
    # stateFileSeeds) and left alone on every launch after -- the same
    # "carve a file out of an otherwise host-owned tree" pattern antigravity
    # uses for .gemini/config/config.json.
    stateFiles = [ ".pi/agent/models.json" ];
    # OpenCode's own model catalog is public and unauthenticated at
    # https://opencode.ai/zen/v1/models -- what a real API key restricts is
    # *calling* a model, not seeing that it exists. Shipping the full list
    # means every model is selectable via --provider opencode-zen --model
    # <id> out of the box; one this account's key doesn't cover just fails
    # at call time with whatever error OpenCode Zen gives for that, same as
    # it would if the user had typed the id in by hand. Regenerate
    # opencode-models.json from that endpoint when the catalog changes.
    stateFileSeeds = {
      ".pi/agent/models.json" = builtins.readFile ./opencode-models.json;
    };
  }
]

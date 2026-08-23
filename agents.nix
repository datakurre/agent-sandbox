# An agent is a CLI command plus the home paths that persist its login state.
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
    creditLimitArg = [
      "--max-ai-credits"
    ];
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
    state = [
      ".pi"
      ".local/share/pi"
      ".config/pi"
      ".cache/pi"
    ];
  }
]

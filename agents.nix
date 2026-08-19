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
    command = [
      "codex"
      "."
    ];
    programmaticArgs = [
      "-p"
      "-"
    ];
    state = [
      ".codex"
    ];
  }
]

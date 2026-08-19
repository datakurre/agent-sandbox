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
    command = [
      "codex"
      "."
    ];
    programmaticArgs = [
      "-p"
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
    package = pkgs.writeShellScriptBin "pi" ''
      exec npx -y @earendil-works/pi-coding-agent "$@"
    '';
    command = [
      "pi"
      "."
    ];
    programmaticArgs = [
      "-p"
      "-"
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

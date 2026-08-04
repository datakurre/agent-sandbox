# An agent is a CLI plus the home paths that persist its login state.
{ pkgs }:
[
  {
    name = "opencode";
    package = pkgs.opencode;
    command = [
      "${pkgs.opencode}/bin/opencode"
      "."
    ];
    state = [
      ".local/share/opencode"
      ".config/opencode"
      ".cache/opencode"
    ];
  }
  {
    name = "claude-code";
    package = pkgs.claude-code;
    command = [ "${pkgs.claude-code}/bin/claude" ];
    state = [ ".claude" ];
    stateFiles = [ ".claude.json" ];
  }
  {
    name = "copilot";
    package = pkgs.github-copilot-cli;
    command = [ "${pkgs.github-copilot-cli}/bin/copilot" ];
    state = [ ".copilot" ];
  }
  {
    name = "antigravity";
    package = pkgs.google-antigravity-cli;
    command = [
      "${pkgs.google-antigravity-cli}/bin/agy"
      "."
    ];
    state = [
      ".local/share/antigravity-cli"
      ".config/antigravity-cli"
      ".cache/antigravity-cli"
      ".gemini"
    ];
  }
]

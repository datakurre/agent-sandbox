{ pkgs, lib }:

let
  # Full rootless podman stack (c.f. devenv-module-devcontainer/tweaks/podman.nix):
  # the extra binaries let nested podman build/run work inside the container when
  # it is launched with enough privileges; the host socket forward below gives a
  # reliable "sibling container" mode that needs no privileges.
  podmanStack = with pkgs; [
    podman
    crun
    conmon
    skopeo
    slirp4netns
    fuse-overlayfs
  ];

  # `docker` alias so anything calling docker hits podman.
  dockerAlias = pkgs.writeShellScriptBin "docker" ''exec ${pkgs.podman}/bin/podman "$@"'';

  baseTools =
    with pkgs;
    [
      openssh
      bashInteractive
      coreutils
      findutils
      gnugrep
      gnupg
      gnused
      gawk
      which
      curl
      wget
      ripgrep
      procps
      fd
      jq
      diffutils
      patch
      file
      tree
      gnutar
      gzip
      unzip
      xz
      bzip2
      zstd
      python3
      uv
      gnumake
      vim
      less
      man-db
      man-pages
      tmux
      htop
      lsof
      strace
      rsync
      perl
      sudo
      shadow
      util-linux
      iproute2
      nettools
      dnsutils
      openssl
      git-lfs
      nix
      devenv
      git
      gh
      nodejs
      opencode
      stdenv.cc.cc.lib
      zlib
      glibcLocales
    ]
    ++ podmanStack
    ++ [ dockerAlias ];

  nixConf = pkgs.writeTextFile {
    name = "nix-conf";
    destination = "/etc/nix/nix.conf";
    text = ''
      sandbox = false
      filter-syscalls = false
      experimental-features = nix-command flakes
    '';
  };

  # Rootless podman container config baked into the image so nested podman is
  # pre-configured. helper_binaries_dir points at the nix store paths so podman
  # inside the image can find crun/fuse-overlayfs without a PATH search.
  containersConf = pkgs.writeTextFile {
    name = "containers-conf";
    destination = "/etc/containers/containers.conf";
    text = ''
      [engine]
      helper_binaries_dir = ["${pkgs.podman}/libexec/podman", "${pkgs.crun}/bin", "${pkgs.fuse-overlayfs}/bin"]
      runtime = "crun"
      [containers]
      pids_limit = 0
    '';
  };

  storageConf = pkgs.writeTextFile {
    name = "storage-conf";
    destination = "/etc/containers/storage.conf";
    text = ''
      [storage]
      driver = "overlay"
    '';
  };

  registriesConf = pkgs.writeTextFile {
    name = "registries-conf";
    destination = "/etc/containers/registries.conf";
    text = ''
      [registries]
      [registries.block]
      registries = []
      [registries.insecure]
      registries = []
      [registries.search]
      registries = ["docker.io", "quay.io"]
    '';
  };

  policyConf = pkgs.writeTextFile {
    name = "policy-conf";
    destination = "/etc/containers/policy.json";
    text = ''
      {"default":[{"type":"insecureAcceptAnything"}],"transports":{"default-daemon":{"":[{"type":"insecureAcceptAnything"}]}}}
    '';
  };

  # All paths baked into the image root, shared between copyToRoot and
  # closureInfo so they stay in sync.
  containerPaths = baseTools ++ [
    pkgs.dockerTools.fakeNss
    pkgs.cacert
    nixConf
    containersConf
    storageConf
    registriesConf
    policyConf
  ];

  # Loaded into the nix DB on first container start so nix treats baked-in
  # store paths as valid and won't attempt to re-substitute them.
  storeRegistration = pkgs.closureInfo { rootPaths = containerPaths; };

  entrypoint = pkgs.writeShellScript "agent-sandbox-entrypoint" ''
    if [[ ! -f /nix/var/nix/db/db.sqlite ]]; then
      nix-store --load-db < /nix/registration
    fi

    # Forward the host gpg-agent into the user's gnupg home so signed
    # commits / git tag operations inside the container reuse host keys.
    if [[ "''${AGENT_SANDBOX_GPG_AGENT:-}" == "1" && -S /run/host-gpg-agent ]]; then
      mkdir -p ~/.gnupg
      rm -f ~/.gnupg/S.gpg-agent
      ln -s /run/host-gpg-agent ~/.gnupg/S.gpg-agent

      # Populate gpg public keyring from the host's read-only gnupg mount
      # so gpg can identify which key the forwarded agent should use.
      if [[ -d /run/host-gnupg ]]; then
        for f in /run/host-gnupg/*; do
          name=$(basename "$f")
          [[ "$name" == "S.gpg-agent"     ]] && continue
          [[ "$name" == "S.gpg-agent."*   ]] && continue
          [[ "$name" == "sshcontrol"      ]] && continue
          [[ "$name" == "private-keys-v1.d"    ]] && continue
          [[ "$name" == "crls.d"          ]] && continue
          [[ -e ~/.gnupg/$name ]] && continue
          cp --no-preserve=mode "$f" ~/.gnupg/ 2>/dev/null || true
        done
      fi

      # Also try to import the signing key's public key from keyserver
      # as a fallback in case the host keyring didn't have it.
      if signing_key=$(git config --get user.signingkey 2>/dev/null); then
        gpg --keyserver keyserver.ubuntu.com --recv-keys "$signing_key" 2>/dev/null || true
      fi
    fi

    exec "$@"
  '';

  image = pkgs.dockerTools.buildImage {
    name = "agent-sandbox";
    tag = "latest";

    copyToRoot = pkgs.buildEnv {
      name = "agent-sandbox-root";
      paths = containerPaths;
    };

    extraCommands = ''
      mkdir -p usr/bin
      ln -s ${pkgs.coreutils}/bin/env usr/bin/env

      # ELF interpreter required by prebuilt native binaries shipped by npm packages
      # (lightningcss, esbuild, @swc/core, etc. all hard-code /lib64/ld-linux-x86-64.so.2)
      mkdir -p lib64
      ln -sf ${pkgs.glibc}/lib/ld-linux-x86-64.so.2 lib64/ld-linux-x86-64.so.2

      mkdir -p home/user
      chmod 1777 home/user
      mkdir -p workspace
      chmod 1777 workspace
      mkdir -p tmp
      chmod 1777 tmp
      mkdir -p var
      chmod u+w var
      mkdir -p var/tmp
      chmod 1777 var/tmp

      mkdir -p nix/store
      chmod 1777 nix/store

      mkdir -p nix/var/nix/db
      mkdir -p nix/var/nix/profiles
      mkdir -p nix/var/nix/gcroots/profiles
      mkdir -p nix/var/nix/temproots
      mkdir -p nix/var/nix/userpool
      mkdir -p nix/var/log/nix/drvs
      chmod -R 1777 nix/var

      cp ${storeRegistration}/registration nix/registration
    '';

    config = {
      WorkingDir = "/workspace";
      Entrypoint = [ "${entrypoint}" ];
      Cmd = [ "${pkgs.opencode}/bin/opencode" ];
      Env = [
        "PATH=${lib.makeBinPath baseTools}"
        "LD_LIBRARY_PATH=${
          lib.makeLibraryPath [
            pkgs.stdenv.cc.cc.lib
            pkgs.zlib
          ]
        }"
        "HOME=/home/user"
        "USER=user"
        "TERM=xterm-256color"
        "SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
        "NIX_SSL_CERT_FILE=${pkgs.cacert}/etc/ssl/certs/ca-bundle.crt"
        "LANG=en_US.UTF-8"
        "LOCALE_ARCHIVE=${pkgs.glibcLocales}/lib/locale/locale-archive"
        # Force Go programs to use the C library (glibc) DNS resolver.
        # Go's pure-Go resolver sends raw UDP queries that time out on
        # slirp4netns's DNS forwarder in rootless Podman, causing 5s delays.
        "GODEBUG=netdns=cgo"
      ];
    };
  };

  loadScript = pkgs.writeShellScriptBin "agent-sandbox-load" ''
    set -euo pipefail
    echo "Loading agent-sandbox image into podman..."
    ${pkgs.podman}/bin/podman load < ${image}
    echo "Done. Run 'agent-sandbox' to start a session."
  '';

  purgeScript = pkgs.writeShellScriptBin "agent-sandbox-purge" ''
    set -euo pipefail

    force=0
    while [[ $# -gt 0 ]]; do
      case "$1" in
        -f|--force) force=1 ;;
        *) echo "Unknown option: $1" >&2; exit 1 ;;
      esac
      shift
    done

    confirm() {
      if [[ "$force" == "1" ]]; then
        return 0
      fi
      local ans
      read -r -p "$1 [y/N] " ans
      [[ "$ans" =~ ^[Yy] ]]
    }

    PODMAN="${pkgs.podman}/bin/podman"

    echo "=== agent-sandbox-purge ==="
    echo

    # ── Containers ────────────────────────────────────────────────
    containers=$("$PODMAN" ps -a \
      --filter ancestor=localhost/agent-sandbox:latest \
      -q 2>/dev/null || true)
    if [[ -n "$containers" ]]; then
      echo "Agent-sandbox containers:"
      "$PODMAN" ps -a \
        --filter ancestor=localhost/agent-sandbox:latest \
        --format "  {{.ID}}  {{.Names}}  {{.Status}}"
      echo
      if confirm "Remove these containers?"; then
        echo "$containers" | xargs -r "$PODMAN" rm -f
        echo "Containers removed."
      else
        echo "Skipped."
      fi
    else
      echo "No agent-sandbox containers found."
    fi
    echo

    # ── Volumes ───────────────────────────────────────────────────
    volumes=$("$PODMAN" volume ls \
      --filter name=agent-sandbox -q 2>/dev/null || true)
    if [[ -n "$volumes" ]]; then
      echo "Agent-sandbox volumes:"
      "$PODMAN" volume ls --filter name=agent-sandbox
      echo
      if confirm "Remove these volumes?"; then
        echo "$volumes" | xargs -r "$PODMAN" volume rm -f
        echo "Volumes removed."
      else
        echo "Skipped."
      fi
    else
      echo "No agent-sandbox volumes found."
    fi
    echo

    # ── Image ─────────────────────────────────────────────────────
    if "$PODMAN" image exists localhost/agent-sandbox:latest 2>/dev/null; then
      echo "Image: localhost/agent-sandbox:latest"
      echo
      if confirm "Remove this image?"; then
        "$PODMAN" rmi -f localhost/agent-sandbox:latest
        echo "Image removed."
      else
        echo "Skipped."
      fi
    else
      echo "No agent-sandbox image found."
    fi

    echo
    echo "Done."
  '';

  # Usage:
  #   agent-sandbox [FLAGS] [-- PODMAN_ARGS...] [-- COMMAND...]
  #
  # The default command inside the container is opencode.  If the current
  # directory contains a devenv.nix, opencode is launched inside a devenv
  # shell (`devenv shell -- opencode .`).  Pass a different command after --
  #
  # Podman run arguments (--privileged, --network=host, …) also go after --.
  #
  # -v SOURCE:DEST[:OPTIONS]  Standard podman volume mount (processed
  #   before --).  Relative paths are expanded automatically:
  #     SOURCE  relative paths are expanded to absolute ($PWD/...)
  #     DEST    relative paths are prefixed with /workspace/
  #             use "." as DEST to mean /workspace itself
  #
  # Integrations (all ON by default, disable with the --no-* flag):
  #   --workspace / --no-workspace
  #                              mount CWD as /workspace/<dirname>:rw
  #                              (default: on; no mount = empty /workspace)
  #   --ssh / --no-ssh           forward SSH_AUTH_SOCK into the container
  #   --git / --no-git           mount ~/.gitconfig and forward git identity
  #   --gpg-agent / --no-gpg-agent
  #                              forward the host gpg-agent socket so host
  #                              gpg keys are usable for signing inside
  #   --gpg-sign / --no-gpg-sign enable/disable git commit signing (default: on,
  #                              disabled via env override when off)
  #   --opencode / --no-opencode mount opencode config/share/cache dirs
  #   --devenv / --no-devenv     mount ~/.local/share/devenv (persisted
  #                              devenv state)
  #   --podman / --no-podman     forward the host rootless podman socket so the
  #                              container's podman client can run sibling
  #                              containers on the host daemon. (The image also
  #                              ships a full nested-capable podman stack + config
  #                              under /etc/containers for privileged launches.)
  #
  # Examples:
  #   agent-sandbox                                       # opencode in CWD
  #   agent-sandbox -- bash                               # bash shell instead
  #   agent-sandbox --no-podman --no-ssh                   # selective opt-out
  #   agent-sandbox --no-gpg-sign                         # disable commit signing
  #   agent-sandbox --no-workspace                         # no CWD mount
  #   agent-sandbox -v ~/src:/workspace/mysrc:rw             # custom workspace
  #   agent-sandbox -- --privileged                         # enable nested podman
  launcher = pkgs.writeShellScriptBin "agent-sandbox" ''
    set -euo pipefail

    if ! ${pkgs.podman}/bin/podman image exists localhost/agent-sandbox:latest 2>/dev/null; then
      echo "agent-sandbox image not found. Run 'agent-sandbox-load' first." >&2
      exit 1
    fi

    # Expand relative paths in -v specs
    expand_v() {
      local spec="$1"
      local src dest opts
      IFS=':' read -r src dest opts <<< "$spec"
      src="''${src/#\~/$HOME}"
      [[ "$src" == "." ]] && src="$PWD"
      [[ "$src" != /* ]] && src="$PWD/$src"
      if [[ -n "$dest" && "$dest" != /* ]]; then
        [[ "$dest" == "." ]] && dest="/workspace" || dest="/workspace/$dest"
      fi
      echo "$src:$dest''${opts:+:$opts}"
    }

    # Integration toggles - all enabled by default.
    want_ssh=1
    want_git=1
    want_gpg=1
    want_gpg_sign=1
    want_opencode=1
    want_podman=1
    want_devenv=1
    want_workspace=1

    mounts=()
    env_args=()
    podman_args=()
    if [[ -f "$PWD/devenv.nix" ]]; then
      cmd_args=("${pkgs.devenv}/bin/devenv" "shell" "--" "${pkgs.opencode}/bin/opencode" ".")
    else
      cmd_args=("${pkgs.opencode}/bin/opencode" ".")
    fi

    while [[ $# -gt 0 ]]; do
      case "$1" in
        --ssh)          want_ssh=1 ;;
        --no-ssh)       want_ssh=0 ;;
        --git)          want_git=1 ;;
        --no-git)       want_git=0 ;;
        --gpg-agent)    want_gpg=1 ;;
        --no-gpg-agent) want_gpg=0 ;;
        --gpg-sign)     want_gpg_sign=1 ;;
        --no-gpg-sign)  want_gpg_sign=0 ;;
        --opencode)     want_opencode=1 ;;
        --no-opencode)  want_opencode=0 ;;
        --devenv)       want_devenv=1 ;;
        --no-devenv)    want_devenv=0 ;;
        --podman)       want_podman=1 ;;
        --no-podman)    want_podman=0 ;;
        --workspace)    want_workspace=1 ;;
        --no-workspace) want_workspace=0 ;;
        -v)  shift; mounts+=("-v" "$(expand_v "$1")") ;;
        -v*) mounts+=("-v" "$(expand_v "''${1#-v}")") ;;
        --) shift; break ;;
        *)   podman_args+=("$1") ;;
      esac
      shift
    done

    # Everything after -- overrides the container command (default: opencode).
    if [[ $# -gt 0 ]]; then
      cmd_args=("$@")
    fi

    if [[ "$want_workspace" == "1" ]]; then
      workspace_name=$(basename "$PWD")
      workspace_dir="/workspace/$workspace_name"
      mounts+=("-v" "$PWD:$workspace_dir:rw")
    else
      workspace_dir="/workspace"
    fi

    if [[ "$want_ssh" == "1" && -S "''${SSH_AUTH_SOCK:-}" ]]; then
      mounts+=("-v" "$SSH_AUTH_SOCK:/agent.sock:rw")
      env_args+=("-e" "SSH_AUTH_SOCK=/agent.sock")
    fi

    if [[ "$want_git" == "1" && -f "$HOME/.gitconfig" ]]; then
      mounts+=("-v" "$HOME/.gitconfig:/home/user/.gitconfig:ro")
      git_name=$(${pkgs.git}/bin/git config --global user.name 2>/dev/null || true)
      git_email=$(${pkgs.git}/bin/git config --global user.email 2>/dev/null || true)
      [[ -n "$git_name" ]]  && env_args+=("-e" "GIT_AUTHOR_NAME=$git_name"   "-e" "GIT_COMMITTER_NAME=$git_name")
      [[ -n "$git_email" ]] && env_args+=("-e" "GIT_AUTHOR_EMAIL=$git_email" "-e" "GIT_COMMITTER_EMAIL=$git_email")
    fi

    if [[ "$want_gpg" == "1" ]]; then
      gpg_socket="''${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/gnupg/S.gpg-agent"
      if [[ -S "$gpg_socket" ]]; then
        mounts+=("-v" "$gpg_socket:/run/host-gpg-agent:ro")
        env_args+=("-e" "AGENT_SANDBOX_GPG_AGENT=1")
        env_args+=("-e" "GPG_TTY=/dev/pts/0")
      fi
      if [[ -d "$HOME/.gnupg" ]]; then
        mounts+=("-v" "$HOME/.gnupg:/run/host-gnupg:ro")
      fi
    fi

    if [[ "$want_gpg_sign" == "0" ]]; then
      env_args+=("-e" "GIT_CONFIG_COUNT=1")
      env_args+=("-e" "GIT_CONFIG_KEY_0=commit.gpgsign")
      env_args+=("-e" "GIT_CONFIG_VALUE_0=false")
    fi

    if [[ "$want_opencode" == "1" ]]; then
      mkdir -p "$HOME/.local/share/opencode" "$HOME/.config/opencode" "$HOME/.cache/opencode"
      mounts+=("-v" "$HOME/.local/share/opencode:/home/user/.local/share/opencode:rw")
      mounts+=("-v" "$HOME/.config/opencode:/home/user/.config/opencode:rw")
      mounts+=("-v" "$HOME/.cache/opencode:/home/user/.cache/opencode:rw")
    fi

    if [[ "$want_devenv" == "1" ]]; then
      mkdir -p "$HOME/.local/share/devenv"
      mounts+=("-v" "$HOME/.local/share/devenv:/home/user/.local/share/devenv:rw")
    fi

    if [[ "$want_podman" == "1" ]]; then
      host_socket="''${XDG_RUNTIME_DIR:-/run/user/$(id -u)}/podman/podman.sock"
      if [[ -S "$host_socket" ]]; then
        mounts+=("-v" "$host_socket:/run/podman/podman.sock:rw")
        env_args+=("-e" "CONTAINER_HOST=unix:///run/podman/podman.sock")
        env_args+=("-e" "DOCKER_HOST=unix:///run/podman/podman.sock")
      else
        echo "Warning: podman socket not found at $host_socket (nested podman still available)" >&2
      fi
    fi

    # Temp passwd/group so tools resolve username correctly inside container
    passwd_tmp=$(mktemp)
    group_tmp=$(mktemp)
    trap 'rm -f "$passwd_tmp" "$group_tmp"' EXIT
    printf 'root:x:0:0:root:/root:/bin/sh\nuser:x:%s:%s::/home/user:/bin/bash\nnobody:x:65534:65534:Nobody:/:/bin/sh\n' "$(id -u)" "$(id -g)" > "$passwd_tmp"
    printf 'root:x:0:\nuser:x:%s:\nnobody:x:65534:\n' "$(id -g)" > "$group_tmp"

    env_args+=("-e" "TERM=''${TERM:-xterm-256color}")
    [[ -n "''${COLORTERM:-}" ]] && env_args+=("-e" "COLORTERM=$COLORTERM")

    ${pkgs.podman}/bin/podman run \
      --rm \
      --interactive \
      --tty \
      --userns=keep-id \
      --workdir "$workspace_dir" \
      -e HOME=/home/user \
      -v "$passwd_tmp:/etc/passwd:ro" \
      -v "$group_tmp:/etc/group:ro" \
      --mount type=tmpfs,dst=/home/user/.config,U=true \
      --mount type=tmpfs,dst=/home/user/.cache,U=true \
      --mount type=tmpfs,dst=/home/user/.local,U=true \
      "''${mounts[@]}" \
      "''${env_args[@]}" \
      "''${podman_args[@]}" \
      localhost/agent-sandbox:latest \
      "''${cmd_args[@]}"
  '';

in
pkgs.symlinkJoin {
  name = "agent-sandbox";
  paths = [
    launcher
    loadScript
    purgeScript
  ];
  meta = {
    description = "Sandboxed AI coding environment via podman";
    mainProgram = "agent-sandbox";
    platforms = lib.platforms.linux;
  };
}

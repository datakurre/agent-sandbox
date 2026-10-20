#!/usr/bin/env bash
# What the entrypoint hands Maven under --proxy (docs/architecture.md, "Maven").
#
# Maven reads its proxy only from settings, so the entrypoint writes global
# settings and names them in MAVEN_ARGS (bin/mvn) and MAVEN_CONFIG (a jar-based
# mvnw), and gives the JVM a truststore when an L7 rule means the session CA.
# This checks that wiring inside a real container.  It needs no JDK and no
# egress: whether Maven then honours it was established by hand against
# Maven 3.9 and 4, and is not something a container can add to.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image

ws="$(make_workspace)"
trap 'rm -rf "$ws"; cleanup_sandboxes' EXIT
cd "$ws" || exit 1

settings='$HOME/.config/agent-sandbox/maven-settings.xml'
show='echo "ARGS=$MAVEN_ARGS;"; echo "CONFIG=$MAVEN_CONFIG;"; echo "OPTS=$MAVEN_OPTS;"; echo "HOST=$AGENT_SANDBOX_PROXY_HOST;"'

# An L7 rule, so the session CA is handed over and Java needs it too.
cat > AGENTS.md <<'EOF'
```toml agent-sandbox
[[network.allowed_routes]]
host = "repo.maven.apache.org"
method = "GET"
path = "/maven2/**"
```
EOF

out="$(sandbox_run --workspace --proxy -- bash -c "$show; cat $settings; \
  od -An -tx1 -N4 ~/.cache/agent-sandbox-ca-bundle.jks; ls ~/.m2/settings.xml 2>&1 || true")"
assert_contains "$out" "ARGS=-gs /home/user/.config/agent-sandbox/maven-settings.xml" "MAVEN_ARGS names the global settings"
assert_contains "$out" "CONFIG=-gs /home/user/.config/agent-sandbox/maven-settings.xml" "MAVEN_CONFIG names them for a jar-based mvnw"
assert_contains "$out" "-Dhttps.proxyHost=" "MAVEN_OPTS carries the JVM proxy"
assert_contains "$out" "-Djavax.net.ssl.trustStore=/home/user/.cache/agent-sandbox-ca-bundle.jks" "MAVEN_OPTS names the truststore under L7"
assert_not_contains "$out" "nonProxyHosts=" "MAVEN_OPTS has nothing Maven 4's eval would read as a pipe"
assert_contains "$out" "<protocol>https</protocol>" "the global settings carry an https proxy"
assert_not_contains "$out" "HOST=;" "the sidecar address is exported for operator settings"
assert_contains "$out" "fe ed fe ed" "the truststore is a JKS keystore"
assert_contains "$out" "No such file" "no fallback user settings when the global ones went out"
assert_not_contains "$out" "entrypoint: --proxy and Maven" "no warning on the normal path"

# The operator's own global settings: theirs is left alone, and the fallback
# carries the proxy in ~/.m2/settings.xml instead.
out="$(sandbox_run --workspace --proxy --podman-args -e MAVEN_ARGS='-gs /etc/theirs.xml' -- \
  bash -c "$show; head -1 ~/.m2/settings.xml")"
assert_contains "$out" "ARGS=-gs /etc/theirs.xml" "an operator's -gs in MAVEN_ARGS is kept"
assert_not_contains "$out" "ARGS=-gs /home/user" "and ours is not put in front of it"
assert_contains "$out" "written by agent-sandbox for its proxy" "the fallback user settings"

# ...unless ~/.m2/settings.xml is the operator's, which is never touched.
# `z`, because --podman-args volumes get no SELinux label from the launcher.
mkdir -p "$ws/m2"
echo '<settings/>' > "$ws/m2/settings.xml"
out="$(sandbox_run --workspace --proxy --podman-args -e MAVEN_ARGS='-gs /etc/theirs.xml' \
  -v "$ws/m2:/home/user/.m2:ro,z" -- bash -c 'cat ~/.m2/settings.xml')"
assert_contains "$out" "<settings/>" "an operator's mounted settings.xml is left as it was"
assert_contains "$out" "entrypoint: --proxy and Maven:" "and the gap is reported"
assert_contains "$out" '${env.AGENT_SANDBOX_PROXY_HOST}' "with advice that survives the next launch"

# A writable ~/.m2 from the host, with no settings.xml in it: the fallback must
# not be written there, or it would outlive the session and send host builds
# to a sidecar that is gone.
rm -f "$ws/m2/settings.xml"
out="$(sandbox_run --workspace --proxy --podman-args -e MAVEN_ARGS='-gs /etc/theirs.xml' \
  -v "$ws/m2:/home/user/.m2:z" -- true)"
assert_eq "$(ls -A "$ws/m2")" "" "a host-mounted ~/.m2 after the session"
assert_contains "$out" "mounted from the host" "and the gap is reported"

# An L4-only policy: no CA, so no truststore.
cat > AGENTS.md <<'EOF'
```toml agent-sandbox
[network]
allowed_hosts = ["repo.maven.apache.org:443"]
```
EOF
out="$(sandbox_run --workspace --proxy -- bash -c "$show; ls ~/.cache/agent-sandbox-ca-bundle.jks 2>&1 || true")"
assert_contains "$out" "ARGS=-gs" "MAVEN_ARGS under an L4-only policy"
assert_not_contains "$out" "trustStore" "no truststore without an L7 rule"

# Without --proxy nothing is set at all.
out="$(sandbox_run --workspace -- bash -c "$show; for f in $settings ~/.m2/settings.xml; do [ -e \"\$f\" ] && echo \"present: \$f\"; done; true")"
for var in ARGS CONFIG OPTS HOST; do
  assert_contains "$out" "$var=;" "$var without --proxy"
done
assert_not_contains "$out" "present:" "no global settings without --proxy"

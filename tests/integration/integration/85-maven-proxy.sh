#!/usr/bin/env bash
# What the entrypoint hands Maven and Java under --proxy (docs/architecture.md, "Maven").
#
# Maven reads its proxy only from settings, so the entrypoint writes global
# settings and names them in MAVEN_ARGS (bin/mvn) and MAVEN_CONFIG (a jar-based
# mvnw), and gives JVMs a truststore when an L7 rule means the session CA.
# This checks that wiring inside a real container. It needs no egress:
# whether Maven then honours it was established by hand against Maven 3.9
# and 4, and is not something a container can add to. A JDK is optional; when
# present, keytool exercises an actual JVM load of the generated truststore.
source "$(dirname "${BASH_SOURCE[0]}")/../lib.sh"
require_image

ws="$(make_workspace)"
trap 'rm -rf "$ws"; cleanup_sandboxes' EXIT
cd "$ws" || exit 1

settings='$HOME/.config/agent-sandbox/maven-settings.xml'
show='echo "ARGS=$MAVEN_ARGS;"; echo "CONFIG=$MAVEN_CONFIG;"; echo "OPTS=$MAVEN_OPTS;"; echo "JTO=$JAVA_TOOL_OPTIONS;"; echo "HOST=$AGENT_SANDBOX_PROXY_HOST;"'

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
  od -An -tx1 -N4 ~/.cache/agent-sandbox-ca-bundle.jks; ls ~/.m2/settings.xml 2>&1 || true; \
  if command -v keytool >/dev/null 2>&1; then \
    keytool -list -keystore ~/.cache/agent-sandbox-ca-bundle.jks -storepass changeit -storetype JKS >/dev/null && echo TRUSTSTORE_JVM_LOAD_OK; \
  else echo TRUSTSTORE_JVM_LOAD_SKIPPED; fi; \
  grep '^JAVA_TOOL_OPTIONS=' ~/.config/agent-sandbox/env")"
assert_contains "$out" "ARGS=-gs /home/user/.config/agent-sandbox/maven-settings.xml" "MAVEN_ARGS names the global settings"
assert_contains "$out" "CONFIG=-gs /home/user/.config/agent-sandbox/maven-settings.xml" "MAVEN_CONFIG names them for a jar-based mvnw"
assert_contains "$(grep '^OPTS=' <<<"$out")" "-Dhttps.proxyHost=" "MAVEN_OPTS carries the JVM proxy"
assert_contains "$(grep '^OPTS=' <<<"$out")" "-Dhttps.proxyPort=" "MAVEN_OPTS carries the https proxy port"
assert_contains "$(grep '^OPTS=' <<<"$out")" "-Dhttp.proxyHost=" "MAVEN_OPTS carries the http proxy host"
assert_contains "$(grep '^OPTS=' <<<"$out")" "-Dhttp.proxyPort=" "MAVEN_OPTS carries the http proxy port"
assert_contains "$(grep '^OPTS=' <<<"$out")" "-Djavax.net.ssl.trustStore=/home/user/.cache/agent-sandbox-ca-bundle.jks" "MAVEN_OPTS names the truststore under L7"
assert_contains "$(grep '^OPTS=' <<<"$out")" "-Djavax.net.ssl.trustStoreType=JKS" "MAVEN_OPTS names the truststore type under L7"
assert_contains "$(grep '^JTO=' <<<"$out")" "JTO=-Dhttp.proxyHost=" "JAVA_TOOL_OPTIONS carries the JVM proxy"
assert_contains "$(grep '^JTO=' <<<"$out")" "-Dhttp.proxyPort=" "JAVA_TOOL_OPTIONS carries the http proxy port"
assert_contains "$(grep '^JTO=' <<<"$out")" "-Dhttps.proxyHost=" "JAVA_TOOL_OPTIONS carries the https proxy host"
assert_contains "$(grep '^JTO=' <<<"$out")" "-Dhttps.proxyPort=" "JAVA_TOOL_OPTIONS carries the https proxy port"
assert_contains "$(grep '^JTO=' <<<"$out")" "-Djavax.net.ssl.trustStore=/home/user/.cache/agent-sandbox-ca-bundle.jks" "JAVA_TOOL_OPTIONS names the truststore under L7"
assert_contains "$(grep '^JTO=' <<<"$out")" "-Djavax.net.ssl.trustStoreType=JKS" "JAVA_TOOL_OPTIONS names the truststore type under L7"
assert_contains "$out" "JAVA_TOOL_OPTIONS=-Dhttp.proxyHost=" "JAVA_TOOL_OPTIONS is recorded for attach"
assert_not_contains "$(grep '^OPTS=' <<<"$out")" "nonProxyHosts=" "MAVEN_OPTS has nothing Maven 4's eval would read as a pipe"
assert_contains "$out" "<protocol>https</protocol>" "the global settings carry an https proxy"
assert_not_contains "$out" "HOST=;" "the sidecar address is exported for operator settings"
assert_contains "$out" "fe ed fe ed" "the truststore is a JKS keystore"
assert_contains "$out" "TRUSTSTORE_JVM_LOAD_" "the optional JVM truststore load check ran"
assert_contains "$out" "No such file" "no fallback user settings when the global ones went out"
assert_not_contains "$out" "entrypoint: --proxy and Maven" "no warning on the normal path"

# Maven's later MAVEN_OPTS must not override an operator's proxy in
# JDK_JAVA_OPTIONS. The launcher fixture passes that environment through.
out="$(sandbox_run --workspace --proxy \
  --podman-args -e JDK_JAVA_OPTIONS='-Dhttp.proxyHost=operator.proxy' -- \
  bash -c 'printf "OPTS=%s\nJDK=%s\n" "$MAVEN_OPTS" "$JDK_JAVA_OPTIONS"')"
assert_contains "$out" "OPTS=" "the Maven options line exists before checking absent pairs"
opts_line="$(grep '^OPTS=' <<<"$out")"
assert_not_contains "$opts_line" "-Dhttp.proxyHost=" "MAVEN_OPTS omits the operator-overridden http host"
assert_not_contains "$opts_line" "-Dhttp.proxyPort=" "MAVEN_OPTS omits the matching generated http port"
assert_contains "$opts_line" "-Dhttps.proxyHost=" "MAVEN_OPTS keeps the complete https pair"
assert_contains "$opts_line" "-Dhttps.proxyPort=" "MAVEN_OPTS keeps the https port"
assert_contains "$(grep '^JDK=' <<<"$out")" "JDK=-Dhttp.proxyHost=operator.proxy" "JDK_JAVA_OPTIONS retains the operator's proxy host"
assert_contains "$out" "supply both properties" "the partial pair is clearly warned about"

# A partial port in JAVA_TOOL_OPTIONS is kept verbatim, but neither generated
# member of that scheme's pair is added to either options variable.
out="$(sandbox_run --workspace --proxy \
  --podman-args -e JAVA_TOOL_OPTIONS='-Dhttps.proxyPort=9443' -- \
  bash -c 'printf "OPTS=%s\nJTO=%s\n" "$MAVEN_OPTS" "$JAVA_TOOL_OPTIONS"')"
assert_contains "$out" "OPTS=" "the Maven options line exists before checking absent pairs"
opts_line="$(grep '^OPTS=' <<<"$out")"
jto_line="$(grep '^JTO=' <<<"$out")"
assert_not_contains "$opts_line" "-Dhttps.proxyHost=" "MAVEN_OPTS omits the generated https host"
assert_not_contains "$opts_line" "-Dhttps.proxyPort=" "MAVEN_OPTS omits the generated https port"
assert_not_contains "$jto_line" "-Dhttps.proxyHost=" "JAVA_TOOL_OPTIONS omits the generated https host"
assert_contains "$jto_line" "-Dhttps.proxyPort=9443" "JAVA_TOOL_OPTIONS retains the operator's port"
assert_contains "$out" "supply both properties" "the partial port pair is clearly warned about"

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
for var in ARGS CONFIG OPTS JTO HOST; do
  assert_contains "$out" "$var=;" "$var without --proxy"
done
assert_not_contains "$out" "present:" "no global settings without --proxy"

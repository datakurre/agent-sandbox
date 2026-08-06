#!/usr/bin/env python3
"""Extract sandbox port declarations from a project's AGENTS.md.

The launcher runs this on the host, before `podman run`, against the AGENTS.md
of the workspace it is about to mount.  Declarations live in a fenced block
whose info string is tagged `agent-sandbox`:

    ```toml agent-sandbox
    [ports]
    web = 3000
    api = { container = 8080, host = 18080 }
    db  = { container = 5432, host = 0 }      # 0 = pick a free host port
    ```

Output is one validated mapping per line, in podman's `--publish` syntax:

    BIND:HOST:CONTAINER/PROTO

AGENTS.md is workspace content: on a cloned repo it is attacker-controlled.
So every field is validated to a narrow type here, and the launcher rebuilds
the `-p` flag from the result rather than passing anything through verbatim.
A value like "127.0.0.1 --privileged" cannot survive `ipaddress.ip_address()`.
"""

from __future__ import annotations

import argparse
import dataclasses
import ipaddress
import re
import socket
import sys
import tomllib

BLOCK_TAG = "agent-sandbox"
MAX_PORTS = 32

FENCE_RE = re.compile(r"^ {0,3}(?P<fence>`{3,}|~{3,})(?P<info>.*)$")
NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
DOMAIN_RE = re.compile(r"\A(?:\*\.)?[A-Za-z0-9](?:[A-Za-z0-9_.-]*[A-Za-z0-9])?\Z")

ENTRY_FIELDS = frozenset({"container", "host", "bind", "protocol"})
PROTOCOLS = frozenset({"tcp", "udp"})


class ConfigError(Exception):
    """A declaration in AGENTS.md is missing, malformed, or out of bounds."""


@dataclasses.dataclass(frozen=True)
class Mapping:
    name: str
    bind: str
    host: int
    container: int
    protocol: str

    def spec(self) -> str:
        """Render as a podman --publish operand.  IPv6 binds need brackets."""
        bind = f"[{self.bind}]" if ":" in self.bind else self.bind
        return f"{bind}:{self.host}:{self.container}/{self.protocol}"


def iter_tagged_blocks(text: str):
    """Yield the body of every fenced block tagged `agent-sandbox`.

    Handles both fence characters and the CommonMark rules that actually
    matter here: a closing fence is at least as long as the opening one, uses
    the same character, and carries no info string.
    """
    lines = text.splitlines()
    index = 0
    while index < len(lines):
        opening = FENCE_RE.match(lines[index])
        index += 1
        if not opening:
            continue
        fence = opening.group("fence")
        info = opening.group("info").strip()
        # A backtick fence's info string may not itself contain a backtick.
        if fence[0] == "`" and "`" in info:
            continue

        body: list[str] = []
        while index < len(lines):
            closing = FENCE_RE.match(lines[index])
            if (
                closing
                and closing.group("fence")[0] == fence[0]
                and len(closing.group("fence")) >= len(fence)
                and not closing.group("info").strip()
            ):
                index += 1
                break
            body.append(lines[index])
            index += 1

        if BLOCK_TAG in info.split():
            yield "\n".join(body)


def _port(name: str, field: str, value: object, *, allow_zero: bool = False) -> int:
    # bool is an int subclass; `web = true` must not read as port 1.
    if isinstance(value, bool) or not isinstance(value, int):
        raise ConfigError(f"ports.{name}.{field}: expected an integer, got {value!r}")
    low = 0 if allow_zero else 1
    if not low <= value <= 65535:
        raise ConfigError(f"ports.{name}.{field}: {value} is outside {low}-65535")
    return value


def _bind(name: str, value: object, allow_any_interface: bool) -> str:
    if not isinstance(value, str):
        raise ConfigError(f"ports.{name}.bind: expected a string, got {value!r}")
    literal = "127.0.0.1" if value == "localhost" else value
    try:
        address = ipaddress.ip_address(literal)
    except ValueError as exc:
        raise ConfigError(
            f"ports.{name}.bind: {value!r} is not an IP address literal"
        ) from exc
    if not address.is_loopback and not allow_any_interface:
        raise ConfigError(
            f"ports.{name}.bind: {address} is not a loopback address; "
            f"pass --ports-any-interface to publish there"
        )
    return str(address)


def _protocol(name: str, value: object) -> str:
    if not isinstance(value, str) or value.lower() not in PROTOCOLS:
        raise ConfigError(
            f"ports.{name}.protocol: expected 'tcp' or 'udp', got {value!r}"
        )
    return value.lower()


def parse_entry(name: str, value: object, allow_any_interface: bool) -> Mapping:
    if not NAME_RE.match(name):
        raise ConfigError(f"ports.{name!r}: name must match {NAME_RE.pattern}")

    if isinstance(value, dict):
        unknown = set(value) - ENTRY_FIELDS
        if unknown:
            raise ConfigError(
                f"ports.{name}: unknown field(s) {', '.join(sorted(unknown))}"
            )
        if "container" not in value:
            raise ConfigError(f"ports.{name}: missing required field 'container'")
        container = _port(name, "container", value["container"])
        host = _port(name, "host", value.get("host", container), allow_zero=True)
        bind = _bind(name, value.get("bind", "127.0.0.1"), allow_any_interface)
        protocol = _protocol(name, value.get("protocol", "tcp"))
    else:
        container = _port(name, "container", value)
        host, bind, protocol = container, "127.0.0.1", "tcp"

    return Mapping(
        name=name, bind=bind, host=host, container=container, protocol=protocol
    )


def parse_proxy_allow_ips(text: str) -> list[str]:
    import ipaddress

    ips = []
    for body in iter_tagged_blocks(text):
        try:
            block = tomllib.loads(body)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"malformed TOML in agent-sandbox block: {exc}") from exc

        proxy = block.get("proxy")
        if proxy is None:
            continue
        if not isinstance(proxy, dict):
            raise ConfigError("[proxy] must be a table")

        allow_ips = proxy.get("allow_ips")
        if allow_ips is not None:
            if not isinstance(allow_ips, list):
                raise ConfigError("[proxy].allow_ips must be a list of strings")
            for ip in allow_ips:
                if not isinstance(ip, str):
                    raise ConfigError("[proxy].allow_ips elements must be strings")
                try:
                    ipaddress.ip_network(ip)
                except ValueError as exc:
                    raise ConfigError(f"[proxy].allow_ips: {ip!r} is not a valid IP address or network: {exc}")
                ips.append(ip)
    return ips


def parse_proxy_deny_ips(text: str) -> list[str]:
    import ipaddress

    ips = []
    for body in iter_tagged_blocks(text):
        try:
            block = tomllib.loads(body)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"malformed TOML in agent-sandbox block: {exc}") from exc

        proxy = block.get("proxy")
        if proxy is None:
            continue
        if not isinstance(proxy, dict):
            raise ConfigError("[proxy] must be a table")

        deny_ips = proxy.get("deny_ips")
        if deny_ips is not None:
            if not isinstance(deny_ips, list):
                raise ConfigError("[proxy].deny_ips must be a list of strings")
            for ip in deny_ips:
                if not isinstance(ip, str):
                    raise ConfigError("[proxy].deny_ips elements must be strings")
                try:
                    ipaddress.ip_network(ip)
                except ValueError as exc:
                    raise ConfigError(f"[proxy].deny_ips: {ip!r} is not a valid IP address or network: {exc}")
                ips.append(ip)
    return ips


def parse_proxy_domains(text: str) -> list[str]:
    domains = []
    for body in iter_tagged_blocks(text):
        try:
            block = tomllib.loads(body)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"malformed TOML in agent-sandbox block: {exc}") from exc

        proxy = block.get("proxy")
        if proxy is None:
            continue
        if not isinstance(proxy, dict):
            raise ConfigError("[proxy] must be a table")

        allow_domains = proxy.get("allow_domains")
        if allow_domains is not None:
            if not isinstance(allow_domains, list):
                raise ConfigError("[proxy].allow_domains must be a list of strings")
            for domain in allow_domains:
                if not isinstance(domain, str):
                    raise ConfigError("[proxy].allow_domains elements must be strings")
                if not DOMAIN_RE.match(domain):
                    raise ConfigError(
                        f"[proxy].allow_domains: {domain!r} is not a valid domain name "
                        f"(must match {DOMAIN_RE.pattern})"
                    )
                domains.append(domain)
    return domains


def parse_proxy_deny_domains(text: str) -> list[str]:
    domains = []
    for body in iter_tagged_blocks(text):
        try:
            block = tomllib.loads(body)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"malformed TOML in agent-sandbox block: {exc}") from exc

        proxy = block.get("proxy")
        if proxy is None:
            continue
        if not isinstance(proxy, dict):
            raise ConfigError("[proxy] must be a table")

        deny_domains = proxy.get("deny_domains")
        if deny_domains is not None:
            if not isinstance(deny_domains, list):
                raise ConfigError("[proxy].deny_domains must be a list of strings")
            for domain in deny_domains:
                if not isinstance(domain, str):
                    raise ConfigError("[proxy].deny_domains elements must be strings")
                if not DOMAIN_RE.match(domain):
                    raise ConfigError(
                        f"[proxy].deny_domains: {domain!r} is not a valid domain name "
                        f"(must match {DOMAIN_RE.pattern})"
                    )
                domains.append(domain)
    return domains


def parse_ports(
    text: str, *, allow_any_interface: bool = False, max_ports: int = MAX_PORTS
) -> list[Mapping]:
    mappings: dict[str, Mapping] = {}
    for body in iter_tagged_blocks(text):
        try:
            block = tomllib.loads(body)
        except tomllib.TOMLDecodeError as exc:
            raise ConfigError(f"malformed TOML in agent-sandbox block: {exc}") from exc

        ports = block.get("ports")
        if ports is None:
            continue
        if not isinstance(ports, dict):
            raise ConfigError("[ports] must be a table")

        for name, value in ports.items():
            if name in mappings:
                raise ConfigError(f"ports.{name}: declared more than once")
            mappings[name] = parse_entry(name, value, allow_any_interface)

    if len(mappings) > max_ports:
        raise ConfigError(
            f"{len(mappings)} port mappings declared, limit is {max_ports}"
        )
    return list(mappings.values())


def allocate(mapping: Mapping) -> Mapping:
    """Resolve `host = 0` to a concrete free port.

    Binding and immediately closing races against anything else grabbing the
    port before podman does; the window is small and the failure is a loud
    "address already in use" from podman rather than a silent misroute.
    """
    if mapping.host != 0:
        return mapping
    family = socket.AF_INET6 if ":" in mapping.bind else socket.AF_INET
    kind = socket.SOCK_DGRAM if mapping.protocol == "udp" else socket.SOCK_STREAM
    with socket.socket(family, kind) as sock:
        sock.bind((mapping.bind, 0))
        return dataclasses.replace(mapping, host=sock.getsockname()[1])


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="agent-sandbox-parse-agents",
        description="Emit podman --publish operands declared in an AGENTS.md.",
    )
    parser.add_argument("path", help="path to AGENTS.md")
    parser.add_argument(
        "--ports-any-interface",
        action="store_true",
        help="permit binds outside loopback",
    )
    parser.add_argument(
        "--max", type=int, default=MAX_PORTS, help=f"cap on mappings (default {MAX_PORTS})"
    )
    parser.add_argument(
        "--no-allocate",
        action="store_true",
        help="leave `host = 0` unresolved instead of picking a free port",
    )
    parser.add_argument(
        "--proxy-domains",
        action="store_true",
        help="extract allow_domains from the [proxy] block instead of port mappings",
    )
    parser.add_argument(
        "--proxy-deny-ips",
        action="store_true",
        help="extract deny_ips from the [proxy] block instead of port mappings",
    )
    parser.add_argument(
        "--proxy-deny-domains",
        action="store_true",
        help="extract deny_domains from the [proxy] block instead of port mappings",
    )
    parser.add_argument(
        "--proxy-allow-ips",
        action="store_true",
        help="extract allow_ips from the [proxy] block instead of port mappings",
    )
    args = parser.parse_args(argv)

    try:
        with open(args.path, encoding="utf-8") as handle:
            text = handle.read()
    except FileNotFoundError:
        return 0  # No AGENTS.md is the common case, not an error.
    except OSError as exc:
        print(f"agent-sandbox: cannot read {args.path}: {exc}", file=sys.stderr)
        return 1

    if args.proxy_domains:
        try:
            domains = parse_proxy_domains(text)
            if domains:
                print(" ".join(domains))
        except ConfigError as exc:
            print(f"agent-sandbox: {args.path}: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.proxy_deny_ips:
        try:
            ips = parse_proxy_deny_ips(text)
            if ips:
                print(" ".join(ips))
        except ConfigError as exc:
            print(f"agent-sandbox: {args.path}: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.proxy_allow_ips:
        try:
            ips = parse_proxy_allow_ips(text)
            if ips:
                print(" ".join(ips))
        except ConfigError as exc:
            print(f"agent-sandbox: {args.path}: {exc}", file=sys.stderr)
            return 1
        return 0

    if args.proxy_deny_domains:
        try:
            domains = parse_proxy_deny_domains(text)
            if domains:
                print(" ".join(domains))
        except ConfigError as exc:
            print(f"agent-sandbox: {args.path}: {exc}", file=sys.stderr)
            return 1
        return 0

    try:
        mappings = parse_ports(
            text, allow_any_interface=args.ports_any_interface, max_ports=args.max
        )
        if not args.no_allocate:
            mappings = [allocate(mapping) for mapping in mappings]
    except ConfigError as exc:
        print(f"agent-sandbox: {args.path}: {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"agent-sandbox: cannot allocate a host port: {exc}", file=sys.stderr)
        return 1

    for mapping in mappings:
        print(mapping.spec())
    return 0


if __name__ == "__main__":
    sys.exit(main())

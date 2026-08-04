#!/usr/bin/env python3
"""Unit tests for the AGENTS.md port parser.

Run directly (`python3 lib/test_parse_agents.py`) or via `nix flake check`.
"""

import unittest

from parse_agents import ConfigError, Mapping, parse_ports


def block(body: str, info: str = "toml agent-sandbox") -> str:
    return f"# Project\n\nSome prose.\n\n```{info}\n{body}\n```\n\nMore prose.\n"


def specs(text: str, **kwargs) -> list[str]:
    return [mapping.spec() for mapping in parse_ports(text, **kwargs)]


class TestDiscovery(unittest.TestCase):
    def test_no_file_content(self):
        self.assertEqual(specs(""), [])

    def test_no_tagged_block(self):
        self.assertEqual(specs("# Title\n\n```toml\n[ports]\nweb = 3000\n```\n"), [])

    def test_tagged_block_without_ports_table(self):
        self.assertEqual(specs(block('[agent]\ndefault = "opencode"')), [])

    def test_bare_tag_without_language(self):
        self.assertEqual(
            specs(block("[ports]\nweb = 3000", info="agent-sandbox")),
            ["127.0.0.1:3000:3000/tcp"],
        )

    def test_tilde_fence(self):
        text = "~~~toml agent-sandbox\n[ports]\nweb = 3000\n~~~\n"
        self.assertEqual(specs(text), ["127.0.0.1:3000:3000/tcp"])

    def test_untagged_fence_is_not_scanned(self):
        # A ```toml block that merely *mentions* ports must be ignored.
        text = "```toml\n[ports]\nweb = 9999\n```\n" + block("[ports]\nweb = 3000")
        self.assertEqual(specs(text), ["127.0.0.1:3000:3000/tcp"])

    def test_two_tagged_blocks_merge(self):
        text = block("[ports]\nweb = 3000") + block("[ports]\napi = 8080")
        self.assertEqual(
            specs(text), ["127.0.0.1:3000:3000/tcp", "127.0.0.1:8080:8080/tcp"]
        )

    def test_duplicate_name_across_blocks_is_rejected(self):
        text = block("[ports]\nweb = 3000") + block("[ports]\nweb = 4000")
        with self.assertRaisesRegex(ConfigError, "declared more than once"):
            specs(text)

    def test_unclosed_fence_still_parses(self):
        self.assertEqual(
            specs("```toml agent-sandbox\n[ports]\nweb = 3000\n"),
            ["127.0.0.1:3000:3000/tcp"],
        )

    def test_indented_fence(self):
        self.assertEqual(
            specs("  ```toml agent-sandbox\n  [ports]\n  web = 3000\n  ```\n"),
            ["127.0.0.1:3000:3000/tcp"],
        )


class TestEntryForms(unittest.TestCase):
    def test_bare_integer(self):
        self.assertEqual(specs(block("[ports]\nweb = 3000")), ["127.0.0.1:3000:3000/tcp"])

    def test_table_with_distinct_host(self):
        self.assertEqual(
            specs(block("[ports]\napi = { container = 8080, host = 18080 }")),
            ["127.0.0.1:18080:8080/tcp"],
        )

    def test_table_defaults_host_to_container(self):
        self.assertEqual(
            specs(block("[ports]\napi = { container = 8080 }")),
            ["127.0.0.1:8080:8080/tcp"],
        )

    def test_udp(self):
        self.assertEqual(
            specs(block('[ports]\ndns = { container = 53, protocol = "udp" }')),
            ["127.0.0.1:53:53/udp"],
        )

    def test_ipv6_loopback_is_bracketed(self):
        self.assertEqual(
            specs(block('[ports]\nweb = { container = 3000, bind = "::1" }')),
            ["[::1]:3000:3000/tcp"],
        )

    def test_localhost_normalises(self):
        self.assertEqual(
            specs(block('[ports]\nweb = { container = 3000, bind = "localhost" }')),
            ["127.0.0.1:3000:3000/tcp"],
        )

    def test_host_zero_is_left_alone_by_the_parser(self):
        # allocate() resolves it; parse_ports must not.
        self.assertEqual(
            specs(block("[ports]\ndb = { container = 5432, host = 0 }")),
            ["127.0.0.1:0:5432/tcp"],
        )


class TestValidation(unittest.TestCase):
    def test_malformed_toml(self):
        with self.assertRaisesRegex(ConfigError, "malformed TOML"):
            specs(block("[ports\nweb = 3000"))

    def test_port_out_of_range(self):
        with self.assertRaisesRegex(ConfigError, "outside 1-65535"):
            specs(block("[ports]\nweb = 70000"))

    def test_zero_container_port_rejected(self):
        with self.assertRaisesRegex(ConfigError, "outside 1-65535"):
            specs(block("[ports]\nweb = 0"))

    def test_string_port_rejected(self):
        with self.assertRaisesRegex(ConfigError, "expected an integer"):
            specs(block('[ports]\nweb = "3000"'))

    def test_boolean_is_not_a_port(self):
        with self.assertRaisesRegex(ConfigError, "expected an integer"):
            specs(block("[ports]\nweb = true"))

    def test_unknown_field(self):
        with self.assertRaisesRegex(ConfigError, "unknown field"):
            specs(block("[ports]\nweb = { container = 3000, sudo = 1 }"))

    def test_missing_container_field(self):
        with self.assertRaisesRegex(ConfigError, "missing required field"):
            specs(block("[ports]\nweb = { host = 3000 }"))

    def test_non_loopback_bind_needs_opt_in(self):
        text = block('[ports]\nweb = { container = 3000, bind = "0.0.0.0" }')
        with self.assertRaisesRegex(ConfigError, "not a loopback address"):
            specs(text)
        self.assertEqual(specs(text, allow_any_interface=True), ["0.0.0.0:3000:3000/tcp"])

    def test_bad_protocol(self):
        with self.assertRaisesRegex(ConfigError, "expected 'tcp' or 'udp'"):
            specs(block('[ports]\nweb = { container = 3000, protocol = "sctp" }'))

    def test_ports_must_be_a_table(self):
        with self.assertRaisesRegex(ConfigError, r"\[ports\] must be a table"):
            specs(block("ports = 3000"))

    def test_cap_on_mapping_count(self):
        body = "[ports]\n" + "\n".join(f"p{i} = {4000 + i}" for i in range(33))
        with self.assertRaisesRegex(ConfigError, "limit is 32"):
            specs(block(body))

    def test_name_charset(self):
        with self.assertRaisesRegex(ConfigError, "name must match"):
            specs(block('[ports]\n"we b" = 3000'))


class TestInjection(unittest.TestCase):
    """AGENTS.md is workspace content; nothing in it may become a podman flag."""

    def test_flag_smuggled_through_bind(self):
        with self.assertRaisesRegex(ConfigError, "not an IP address literal"):
            specs(
                block(
                    '[ports]\nweb = { container = 3000, '
                    'bind = "127.0.0.1 --privileged" }'
                )
            )

    def test_flag_smuggled_through_port(self):
        with self.assertRaisesRegex(ConfigError, "expected an integer"):
            specs(block('[ports]\nweb = "3000 -v /:/host"'))

    def test_flag_smuggled_through_protocol(self):
        with self.assertRaisesRegex(ConfigError, "expected 'tcp' or 'udp'"):
            specs(block('[ports]\nweb = { container = 3000, protocol = "tcp -v /:/h" }'))

    def test_emitted_specs_never_contain_whitespace(self):
        text = block(
            "[ports]\n"
            "web = 3000\n"
            'api = { container = 8080, host = 18080, protocol = "udp" }\n'
            'v6  = { container = 9000, bind = "::1" }\n'
        )
        for spec in specs(text):
            self.assertNotIn(" ", spec)
            self.assertRegex(spec, r"^[0-9a-f.:\[\]]+:\d+:\d+/(tcp|udp)$")


class TestAllocate(unittest.TestCase):
    def test_allocate_resolves_zero(self):
        from parse_agents import allocate

        resolved = allocate(
            Mapping(name="db", bind="127.0.0.1", host=0, container=5432, protocol="tcp")
        )
        self.assertGreater(resolved.host, 0)
        self.assertEqual(resolved.container, 5432)

    def test_allocate_leaves_fixed_ports(self):
        from parse_agents import allocate

        fixed = Mapping(
            name="web", bind="127.0.0.1", host=3000, container=3000, protocol="tcp"
        )
        self.assertIs(allocate(fixed), fixed)


if __name__ == "__main__":
    unittest.main()

#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Validate libraries.toml against the jk library registry curation policy.

Checks:
  1. Every entry is `name = "group:artifact"` (no versions, no junk lines).
  2. Short names are unique.
  3. Coordinates are unique (one canonical name per artifact).
  4. Short names use a sensible identifier form.
  5. No redundant vendor/org prefix when the bare artifactId is already a
     distinctive, free short name (the `nats-jnats` anti-pattern).

Exit 0 on success, 1 on any violation. Stdlib only.
"""

from __future__ import annotations

import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
REGISTRY = ROOT / "libraries.toml"

# Lines under [libraries] must match this.
ENTRY_RE = re.compile(
    r"^([a-zA-Z][a-zA-Z0-9_.+-]*)\s*=\s*\"([^\"]+)\"\s*$"
)
NAME_RE = re.compile(r"^[a-z][a-z0-9]*(-[a-z0-9]+)*$")

# ArtifactIds that are too generic / module-ish / service-like to stand alone
# as a short name. Prefixed forms (aws-sdk-s3, zxing-core, …) are expected.
GENERIC_ARTIFACTS = {
    # pure generics / module fragments
    "core",
    "api",
    "bom",
    "common",
    "commons",
    "client",
    "server",
    "runtime",
    "annotations",
    "annotation",
    "util",
    "utils",
    "tools",
    "sdk",
    "spi",
    "impl",
    "base",
    "parent",
    "all",
    "bundle",
    "java",
    "kotlin",
    "test",
    "tests",
    "testing",
    "mock",
    "stubs",
    "proto",
    "protos",
    "value",
    "builder",
    "config",
    "logging",
    "json",
    "xml",
    "yaml",
    "toml",
    "csv",
    "http",
    "mail",
    "cache",
    "jcache",
    "jdbc",
    "jms",
    "web",
    "security",
    "data",
    "messaging",
    "context",
    "beans",
    "aop",
    "tx",
    "orm",
    "expression",
    "jcl",
    "integration",
    "actuator",
    "validation",
    "batch",
    "quartz",
    "amqp",
    "rsocket",
    "hateoas",
    "devtools",
    "dependencies",
    "configuration-processor",
    "compiler",
    "simpleclient",
    "jcc",
    "ucp",
    "ucp11",
    "svm",
    "nativeimage",
    "polyglot",
    "libraries-bom",
    "imageio-core",
    "javase",
    "amqp-client",
    "rewrite-java",
    "apache-client",
    "netty-nio-client",
    "url-connection-client",
    "logging-interceptor",
    "mockwebserver",
    "converter-gson",
    "converter-jackson",
    "converter-kotlinx-serialization",
    "cache-api",
    "validation-api",
    # cloud / infra tokens that need a product family prefix
    "s3",
    "sqs",
    "sns",
    "ses",
    "sts",
    "ssm",
    "kms",
    "rds",
    "lambda",
    "kinesis",
    "dynamodb",
    "cloudwatch",
    "cloudwatchlogs",
    "eventbridge",
    "secretsmanager",
    "dynamodb-enhanced",
    "mysql",
    "postgresql",
    "mariadb",
    "mongodb",
    "cassandra",
    "elasticsearch",
    "kafka",
    "rabbitmq",
    "pulsar",
    "clickhouse",
    "vault",
    "oracle-free",
    "mssqlserver",
    "localstack",
    "gcloud",
    "spock",
    # short acronyms that still need a brand in the alias
    "poi",
    "poi-ooxml",
    "junit-jupiter",
    "querydsl-apt",
    "querydsl-core",
    "querydsl-jpa",
    "querydsl-sql",
    "json-path",
}

# Load-bearing family prefixes: name = "{family}-{artifact}" is fine even
# when artifact is distinctive, because the family is greppable muscle memory.
# (Not used to suppress the vendor-namespace check — that only fires when the
# prefix is drawn from the Maven group.)
FAMILY_PREFIXES = {
    "aws-sdk",
    "testcontainers",
    "spring-boot",
    "spring-boot-starter",
    "spring-security",
    "spring-data",
    "spring-cloud",
    "okhttp",
    "retrofit",
    "jackson2",
    "jackson3",
}


def parse_registry(path: Path) -> tuple[list[tuple[str, str, str, int]], list[str]]:
    """Return (entries, errors). entries are (name, group, artifact, line_no)."""
    errors: list[str] = []
    entries: list[tuple[str, str, str, int]] = []
    in_libraries = False

    text = path.read_text(encoding="utf-8")
    for line_no, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("["):
            in_libraries = line == "[libraries]"
            if line != "[libraries]" and not line.startswith("[libraries."):
                # Allow only the [libraries] table for now.
                errors.append(f"L{line_no}: unexpected table {line!r}")
            continue
        if not in_libraries:
            errors.append(f"L{line_no}: entry outside [libraries]: {line}")
            continue

        m = ENTRY_RE.match(line)
        if not m:
            errors.append(f"L{line_no}: unparseable entry: {line}")
            continue

        name, coord = m.group(1), m.group(2)
        parts = coord.split(":")
        if len(parts) != 2 or not parts[0] or not parts[1]:
            errors.append(
                f"L{line_no}: {name}: coordinate must be exactly "
                f"'group:artifact' (no version); got {coord!r}"
            )
            continue
        group, artifact = parts
        if any(p.strip() != p or " " in p for p in (group, artifact)):
            errors.append(f"L{line_no}: {name}: whitespace in coordinate {coord!r}")
            continue
        entries.append((name, group, artifact, line_no))

    if not in_libraries and not entries:
        errors.append("missing [libraries] table")
    return entries, errors


def prefix_is_from_group(prefix: str, group: str) -> bool:
    """True when prefix is a Maven-group / vendor namespace, not a product family."""
    parts = group.lower().split(".")
    if prefix.lower() in parts:
        return True
    # Common vendor aliases that appear as org path segments or well-known brands.
    vendor_in_group = {
        "google": "google",
        "apache": "apache",
        "oracle": "oracle",
        "findbugs": "findbugs",
        "auth0": "auth0",
        "jetbrains": "jetbrains",
        "typesafe": "typesafe",
        "rabbitmq": "rabbitmq",
        "nats": "nats",
        "prometheus": "prometheus",
        "db2": "db2",
        "ibm": "ibm",
        "amazon": "amazon",
        "awssdk": "awssdk",
        "azure": "azure",
        "eclipse": "eclipse",
        "squareup": "squareup",
    }
    needle = vendor_in_group.get(prefix.lower())
    if needle and needle in parts:
        return True
    return False


def check_redundant_vendor_prefix(
    entries: list[tuple[str, str, str, int]],
) -> list[str]:
    """Flag `vendor-artifact` when bare artifactId is free and distinctive."""
    names = {name for name, _, _, _ in entries}
    errors: list[str] = []

    for name, group, artifact, line_no in entries:
        if name == artifact:
            continue
        if not name.endswith("-" + artifact):
            continue
        prefix = name[: -(len(artifact) + 1)]
        if not prefix:
            continue

        # Family prefixes (aws-sdk-*, testcontainers-*, …) are intentional.
        if prefix in FAMILY_PREFIXES or any(
            name.startswith(f + "-") for f in FAMILY_PREFIXES
        ):
            continue

        if not prefix_is_from_group(prefix, group):
            continue

        if artifact in names:
            # Bare name already taken — prefix disambiguates a real collision.
            continue

        art_l = artifact.lower()
        if art_l in GENERIC_ARTIFACTS or len(artifact) <= 3:
            continue

        errors.append(
            f"L{line_no}: redundant vendor prefix: {name!r} should be "
            f"{artifact!r} (artifactId is already distinctive; coordinate "
            f"{group}:{artifact}). Do not prepend group/vendor just to namespace."
        )
    return errors


def check_name_form(entries: list[tuple[str, str, str, int]]) -> list[str]:
    errors: list[str] = []
    for name, _, _, line_no in entries:
        if not NAME_RE.match(name):
            errors.append(
                f"L{line_no}: short name {name!r} must be lowercase "
                f"kebab-case ([a-z][a-z0-9]*(-[a-z0-9]+)*)"
            )
    return errors


def check_uniqueness(entries: list[tuple[str, str, str, int]]) -> list[str]:
    errors: list[str] = []
    by_name: dict[str, list[int]] = defaultdict(list)
    by_coord: dict[str, list[tuple[str, int]]] = defaultdict(list)

    for name, group, artifact, line_no in entries:
        by_name[name].append(line_no)
        by_coord[f"{group}:{artifact}"].append((name, line_no))

    for name, lines in sorted(by_name.items()):
        if len(lines) > 1:
            errors.append(
                f"duplicate short name {name!r} at lines "
                + ", ".join(str(n) for n in lines)
            )

    for coord, owners in sorted(by_coord.items()):
        if len(owners) > 1:
            detail = ", ".join(f"{n!r} (L{ln})" for n, ln in owners)
            errors.append(
                f"multiple short names for {coord}: {detail} "
                f"(one canonical name per artifact)"
            )
    return errors


def main() -> int:
    if not REGISTRY.is_file():
        print(f"error: registry not found: {REGISTRY}", file=sys.stderr)
        return 1

    entries, errors = parse_registry(REGISTRY)
    if not entries and not errors:
        errors.append("no library entries found")

    errors.extend(check_uniqueness(entries))
    errors.extend(check_name_form(entries))
    errors.extend(check_redundant_vendor_prefix(entries))

    if errors:
        print(f"libraries.toml: {len(errors)} issue(s):\n", file=sys.stderr)
        for e in errors:
            print(f"  • {e}", file=sys.stderr)
        return 1

    print(f"OK: {len(entries)} libraries in {REGISTRY.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

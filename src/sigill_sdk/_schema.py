# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""Validation against the bundled Agent Evidence Profiles v1 JSON Schemas.

Byte-exact copies of ``spec/*.schema.json`` ship under ``_schemas/``.
Implements exactly the JSON Schema keywords those schemas use (type,
required, properties, additionalProperties, const, enum, items, minItems,
minLength, minimum, pattern, format, allOf, anyOf, not, if/then/else,
contains/minContains/maxContains, local $ref). A schema using anything else
is rejected at load time rather than silently half-checked. Error messages
match the .NET SDK byte for byte; the agent-run vectors pin them.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from functools import lru_cache
from importlib import resources
from typing import Any

_RESOURCES = {
    "AgentControlArtifact": "agent-control-artifact-v1.schema.json",
    "AgentExecutionEvidence": "agent-execution-evidence-v1.schema.json",
    "ControlEvaluation": "control-evaluation-v1.schema.json",
}

_SUPPORTED = {
    "$schema", "$id", "$defs", "$ref", "title", "description", "type", "required", "properties",
    "additionalProperties", "const", "enum", "items", "minItems", "minLength", "minimum", "pattern", "format",
    "allOf", "anyOf", "not", "if", "then", "else", "contains", "minContains", "maxContains",
}
_IDENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_UUID = re.compile(r"^(urn:uuid:)?[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$")
_URI_REFERENCE = re.compile(r"^([A-Za-z0-9\-._~:/?#\[\]@!$&'()*+,;=]|%[0-9A-Fa-f]{2})*$")
_DATE_TIME = re.compile(r"^(\d{4}-\d{2}-\d{2})[Tt](\d{2}:\d{2}:\d{2})(?:\.(\d+))?([Zz]|[+-]\d{2}:\d{2})$")


def _check_keywords(node: Any) -> None:
    if isinstance(node, dict):
        unknown = set(node) - _SUPPORTED
        if unknown:
            raise ValueError(f"unsupported JSON Schema keyword(s): {sorted(unknown)}")
        for key in ("properties", "$defs"):
            for sub in (node.get(key) or {}).values():
                _check_keywords(sub)
        for key in ("items", "additionalProperties", "not", "if", "then", "else", "contains"):
            if isinstance(node.get(key), dict):
                _check_keywords(node[key])
        for key in ("allOf", "anyOf"):
            for sub in node.get(key) or []:
                _check_keywords(sub)


@lru_cache(maxsize=None)
def profile_schema(schema_name: str) -> dict:
    """The named profile's schema shipped with the SDK (``AgentControlArtifact``, …)."""
    text = resources.files("sigill_sdk").joinpath("_schemas/" + _RESOURCES[schema_name]).read_text(encoding="utf-8")
    schema = json.loads(text)
    _check_keywords(schema)
    return schema


def parse_date_time(s: str) -> datetime | None:
    """RFC 3339 date-time; fractional seconds of any length."""
    if not isinstance(s, str):
        return None
    m = _DATE_TIME.match(s)
    if not m:
        return None
    date, clock, frac, tz = m.groups()
    frac = (frac or "0")[:6].ljust(6, "0")
    tz = "+00:00" if tz in ("Z", "z") else tz
    try:
        return datetime.fromisoformat(f"{date}T{clock}.{frac}{tz}")
    except ValueError:
        return None


def is_uuid(s: str) -> bool:
    """A UUID; the ``urn:uuid:`` form is accepted (common rules §1)."""
    return isinstance(s, str) and bool(_UUID.match(s))


def _type_ok(v: Any, t: str) -> bool:
    if t == "object":
        return isinstance(v, dict)
    if t == "array":
        return isinstance(v, list)
    if t == "string":
        return isinstance(v, str)
    if t == "boolean":
        return isinstance(v, bool)
    if t == "integer":
        return (isinstance(v, int) and not isinstance(v, bool)) or (isinstance(v, float) and v.is_integer())
    if t == "number":
        return isinstance(v, (int, float)) and not isinstance(v, bool)
    if t == "null":
        return v is None
    return False


def _json_equal(a: Any, b: Any) -> bool:
    """JSON equality: unlike Python ``==``, ``true`` is not ``1``."""
    if isinstance(a, bool) or isinstance(b, bool):
        return isinstance(a, bool) and isinstance(b, bool) and a == b
    if isinstance(a, dict) and isinstance(b, dict):
        return a.keys() == b.keys() and all(_json_equal(a[k], b[k]) for k in a)
    if isinstance(a, list) and isinstance(b, list):
        return len(a) == len(b) and all(_json_equal(x, y) for x, y in zip(a, b))
    if isinstance(a, (int, float)) and isinstance(b, (int, float)):
        return a == b
    return type(a) is type(b) and a == b


def _format_ok(v: str, fmt: str) -> bool:
    if fmt == "date-time":
        return parse_date_time(v) is not None
    if fmt == "uuid":
        return is_uuid(v)
    if fmt == "uri-reference":
        return bool(_URI_REFERENCE.match(v))
    return True


def _child(path: str, key: str) -> str:
    seg = f".{key}" if _IDENT.match(key) else f"['{key}']"
    return seg[1:] if path == "" else path + seg


def _label(path: str) -> str:
    return path or "envelope"


def _number_text(n: Any) -> str:
    return str(int(n)) if isinstance(n, float) and n.is_integer() else str(n)


def _enum_text(e: Any) -> str:
    return e if isinstance(e, str) else json.dumps(e)


def _describe(contains: dict) -> str:
    """'item with role "control-set"' for a contains schema that pins one member, else 'matching item'."""
    props = contains.get("properties")
    if isinstance(props, dict) and len(props) == 1:
        name, sub = next(iter(props.items()))
        if isinstance(sub, dict) and "const" in sub:
            return f"item with {name} {json.dumps(sub['const'])}"
    return "matching item"


def _describe_not(node: dict) -> str:
    """The members a ``not`` forbids, for the shapes the profiles use (required, anyOf of required)."""
    def names(s: dict) -> list[str]:
        return [n for n in s.get("required") or [] if isinstance(n, str)]
    if len(node) == 1 and isinstance(node.get("required"), list):
        return "must not carry " + ", ".join(f"'{n}'" for n in names(node))
    alts = node.get("anyOf")
    if len(node) == 1 and isinstance(alts, list) and all(
            isinstance(a, dict) and len(a) == 1 and isinstance(a.get("required"), list) for a in alts):
        return "must not carry any of " + ", ".join(f"'{n}'" for a in alts for n in names(a))
    return "must not match the disallowed shape"


def _is_valid(instance: Any, schema: dict, root: dict) -> bool:
    return not validate(instance, schema, root)


def validate(instance: Any, schema: dict, root: dict, path: str = "") -> list[str]:
    """Returns every violation of ``schema`` by ``instance``, as messages."""
    errs: list[str] = []
    if "$ref" in schema:
        ref = schema["$ref"]
        if not ref.startswith("#/$defs/"):
            raise ValueError(f"unsupported $ref '{ref}'")
        return validate(instance, root["$defs"][ref[len("#/$defs/"):]], root, path)

    t = schema.get("type")
    if t is not None and not _type_ok(instance, t):
        return [f"{_label(path)} must be of type {t}"]
    if "const" in schema and not _json_equal(instance, schema["const"]):
        errs.append(f"{_label(path)} must equal {json.dumps(schema['const'])}")
    if "enum" in schema and not any(_json_equal(instance, e) for e in schema["enum"]):
        errs.append(f"{_label(path)} must be one of {', '.join(_enum_text(e) for e in schema['enum'])}")
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errs.append(f"{_label(path)} is shorter than {schema['minLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errs.append(f"{_label(path)} does not match {schema['pattern']}")
        if "format" in schema and not _format_ok(instance, schema["format"]):
            errs.append(f"{_label(path)} is not a valid {schema['format']}")
    if _type_ok(instance, "number") and "minimum" in schema and instance < schema["minimum"]:
        errs.append(f"{_label(path)} must be >= {_number_text(schema['minimum'])}")
    if isinstance(instance, list):
        min_items = schema.get("minItems")
        if isinstance(min_items, int) and len(instance) < min_items:
            errs.append(f"{_label(path)} must have at least {min_items} item{'' if min_items == 1 else 's'}")
        if isinstance(schema.get("items"), dict):
            for i, item in enumerate(instance):
                errs.extend(validate(item, schema["items"], root, f"{path}[{i}]" if path else f"[{i}]"))
        if isinstance(schema.get("contains"), dict):
            contains = schema["contains"]
            matches = sum(1 for x in instance if _is_valid(x, contains, root))
            lo = schema.get("minContains", 1)
            hi = schema.get("maxContains")
            if matches < lo:
                errs.append(f"{_label(path)} must contain at least {lo} {_describe(contains)}")
            if hi is not None and matches > hi:
                errs.append(f"{_label(path)} must contain at most {hi} {_describe(contains)}")
    if isinstance(instance, dict):
        for key in schema.get("required") or []:
            if key not in instance:
                errs.append(f"{_label(path)} is missing required member '{key}'")
        props = schema.get("properties") or {}
        additional = schema.get("additionalProperties", True)
        for key, value in instance.items():
            if key in props:
                if isinstance(props[key], dict):
                    errs.extend(validate(value, props[key], root, _child(path, key)))
            elif additional is False:
                errs.append(f"{_label(path)} has unknown member '{key}'")
            elif isinstance(additional, dict):
                errs.extend(validate(value, additional, root, _child(path, key)))
    for sub in schema.get("allOf") or []:
        errs.extend(validate(instance, sub, root, path))
    if "anyOf" in schema and not any(_is_valid(instance, sub, root) for sub in schema["anyOf"]):
        errs.append(f"{_label(path)} must match at least one of the allowed shapes")
    if isinstance(schema.get("not"), dict) and _is_valid(instance, schema["not"], root):
        errs.append(f"{_label(path)} {_describe_not(schema['not'])}")
    if isinstance(schema.get("if"), dict):
        branch = schema.get("then") if _is_valid(instance, schema["if"], root) else schema.get("else")
        if isinstance(branch, dict):
            errs.extend(validate(instance, branch, root, path))
    return errs


def validate_profile(envelope: Any, schema_name: str) -> list[str]:
    """Every violation of the named profile's schema (``AgentControlArtifact``, …)."""
    schema = profile_schema(schema_name)
    return validate(envelope, schema, schema)

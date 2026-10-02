# Licensed to Sigill under the Apache License, Version 2.0.
# SPDX-License-Identifier: Apache-2.0
"""Validation against the bundled AI evidence v2 JSON Schema.

Implements exactly the JSON Schema keywords the v2 schema uses (type,
required, properties, additionalProperties, const, enum, items, minLength,
minimum, pattern, format, local $ref). A schema using anything else is
rejected at load time rather than silently half-checked. Error messages
match the .NET SDK byte for byte; the agent-run vectors pin them.
"""

from __future__ import annotations

import json
import re
from datetime import datetime
from functools import lru_cache
from importlib import resources
from typing import Any

_SUPPORTED = {
    "$schema", "$id", "$defs", "$ref", "title", "description", "type", "required", "properties",
    "additionalProperties", "const", "enum", "items", "minLength", "minimum", "pattern", "format",
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
        for key in ("items", "additionalProperties"):
            if isinstance(node.get(key), dict):
                _check_keywords(node[key])


@lru_cache(maxsize=1)
def envelope_v2_schema() -> dict:
    """The AI evidence v2 envelope schema shipped with the SDK (a byte-exact
    copy of ``spec/ai-evidence-envelope-v2.schema.json``)."""
    text = resources.files("sigill_sdk").joinpath("_schemas/ai-evidence-envelope-v2.schema.json").read_text(
        encoding="utf-8")
    schema = json.loads(text)
    _check_keywords(schema)
    return schema


def parse_date_time(s: str) -> datetime | None:
    """RFC 3339 date-time; fractional seconds of any length."""
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
    """A UUID; the ``urn:uuid:`` form is accepted for compatibility (profile §2)."""
    return bool(_UUID.match(s))


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
    if "const" in schema and instance != schema["const"]:
        errs.append(f"{_label(path)} must equal {json.dumps(schema['const'])}")
    if "enum" in schema and instance not in schema["enum"]:
        errs.append(f"{_label(path)} must be one of {', '.join(str(e) for e in schema['enum'])}")
    if isinstance(instance, str):
        if "minLength" in schema and len(instance) < schema["minLength"]:
            errs.append(f"{_label(path)} is shorter than {schema['minLength']}")
        if "pattern" in schema and not re.search(schema["pattern"], instance):
            errs.append(f"{_label(path)} does not match {schema['pattern']}")
        if "format" in schema and not _format_ok(instance, schema["format"]):
            errs.append(f"{_label(path)} is not a valid {schema['format']}")
    if _type_ok(instance, "number") and "minimum" in schema and instance < schema["minimum"]:
        errs.append(f"{_label(path)} must be >= {_number_text(schema['minimum'])}")
    if isinstance(instance, list) and isinstance(schema.get("items"), dict):
        for i, item in enumerate(instance):
            errs.extend(validate(item, schema["items"], root, f"{path}[{i}]" if path else f"[{i}]"))
    if isinstance(instance, dict):
        for key in schema.get("required") or []:
            if key not in instance:
                errs.append(f"{_label(path)} is missing required member '{key}'")
        props = schema.get("properties") or {}
        additional = schema.get("additionalProperties", True)
        for key, value in instance.items():
            if key in props:
                errs.extend(validate(value, props[key], root, _child(path, key)))
            elif additional is False:
                errs.append(f"{_label(path)} has unknown member '{key}'")
            elif isinstance(additional, dict):
                errs.extend(validate(value, additional, root, _child(path, key)))
    return errs


def validate_envelope_v2(envelope: Any) -> list[str]:
    """Every violation of the AI evidence v2 envelope schema."""
    schema = envelope_v2_schema()
    return validate(envelope, schema, schema)

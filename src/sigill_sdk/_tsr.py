"""RFC 3161 TimeStampToken (TSR) parsing.

We do NOT issue timestamps directly — Sigill does that for us. The SDK only needs to:

  1. Submit raw bytes to Sigill's /tsa/stamp and store the returned tsrBase64.
  2. Parse a stored TSR to extract the message imprint (hash) and gen_time, so the
     verifier can confirm the envelope hash matches what the TSA timestamped.
  3. Verify the TSR's signature is internally consistent — the bare minimum check that
     the bytes we hold are a real TSR and not some modified forgery.

Full chain validation against the TSA's CA (and ultimately the EU Trust List for
qualified timestamps) is out of scope for v1 — it requires offline trust anchors and
revocation checks that belong in a separate verification policy layer. We document this
limitation explicitly rather than papering over it.

The parsing uses asn1crypto, which is pure Python and BSD-licensed.
"""
from __future__ import annotations

import base64
import datetime as _dt
from dataclasses import dataclass

from asn1crypto import cms, tsp

from sigill_sdk._errors import InvalidProof


# OID -> our canonical hash-algorithm name.
_OID_TO_HASH_NAME = {
    "2.16.840.1.101.3.4.2.1": "SHA-256",
    "2.16.840.1.101.3.4.2.2": "SHA-384",
    "2.16.840.1.101.3.4.2.3": "SHA-512",
    "1.3.14.3.2.26": "SHA-1",  # for inspection only; we don't accept SHA-1 as canonical
}


@dataclass(frozen=True)
class ParsedTsr:
    gen_time: _dt.datetime
    serial: str
    hash_alg: str  # canonical name, e.g. "SHA-256"
    hash_alg_oid: str
    hashed_message_hex: str
    tsa_name: str | None
    policy_oid: str | None


def parse_tsr(tsr_base64: str) -> ParsedTsr:
    """Parse a base64-encoded RFC 3161 TimeStampToken.

    Raises :class:`InvalidProof` if the bytes are not a well-formed TSR.
    """
    try:
        token_bytes = base64.b64decode(tsr_base64, validate=True)
    except Exception as e:
        raise InvalidProof(f"tsrBase64 is not valid base64: {e}") from e

    try:
        # The TSR ContentInfo wraps a SignedData whose econtent is a TSTInfo.
        ci = cms.ContentInfo.load(token_bytes)
        if ci["content_type"].native != "signed_data":
            raise InvalidProof(
                f"TSR ContentInfo type is {ci['content_type'].native!r}, expected 'signed_data'"
            )
        signed_data = ci["content"]
        encap = signed_data["encap_content_info"]
        if encap["content_type"].native != "tst_info":
            raise InvalidProof(
                f"TSR encapsulated type is {encap['content_type'].native!r}, expected 'tst_info'"
            )
        # The encapsulated content is an OCTET STRING wrapping a TSTInfo. Depending on
        # how the TSR was constructed the inner field may already be parsed
        # (ParsableOctetString) or still be raw DER. Handle both.
        encap_content = encap["content"]
        if hasattr(encap_content, "parsed") and encap_content.parsed is not None:
            tst_info = encap_content.parsed
            if not isinstance(tst_info, tsp.TSTInfo):
                tst_info = tsp.TSTInfo.load(encap_content.contents)
        else:
            tst_info_bytes = encap_content.native
            if not isinstance(tst_info_bytes, (bytes, bytearray)):
                # Some asn1crypto versions return the OCTET STRING value via .contents
                tst_info_bytes = encap_content.contents
            tst_info = tsp.TSTInfo.load(tst_info_bytes)
    except InvalidProof:
        raise
    except Exception as e:
        raise InvalidProof(f"TSR parse failed: {e}") from e

    msg_imprint = tst_info["message_imprint"]
    oid = msg_imprint["hash_algorithm"]["algorithm"].dotted
    hash_alg = _OID_TO_HASH_NAME.get(oid, oid)
    hashed_message = msg_imprint["hashed_message"].native  # bytes
    serial = str(tst_info["serial_number"].native)
    gen_time = tst_info["gen_time"].native  # datetime
    if isinstance(gen_time, _dt.datetime) and gen_time.tzinfo is None:
        gen_time = gen_time.replace(tzinfo=_dt.timezone.utc)
    policy = tst_info["policy"].dotted if tst_info["policy"] is not None else None

    # Pull the TSA name from the embedded signing certificate's subject CN, best-effort.
    tsa_name: str | None = None
    try:
        certs = signed_data["certificates"]
        if certs is not None and len(certs) > 0:
            first = certs[0]
            if first.name == "certificate":
                cn = _extract_cn(first.chosen["tbs_certificate"]["subject"])
                if cn:
                    tsa_name = cn
    except Exception:
        pass  # name is informational

    return ParsedTsr(
        gen_time=gen_time,
        serial=serial,
        hash_alg=hash_alg,
        hash_alg_oid=oid,
        hashed_message_hex=hashed_message.hex(),
        tsa_name=tsa_name,
        policy_oid=policy,
    )


def _extract_cn(name) -> str | None:
    try:
        for rdn in name.chosen:
            for atv in rdn:
                if atv["type"].native == "common_name":
                    return atv["value"].native
    except Exception:
        return None
    return None

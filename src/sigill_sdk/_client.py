"""SigillClient — seal and verify AI evidence envelopes.

Public API mirrors the .NET interface ISigillAiEvidenceClient. The seal() / verify()
flow is the surface 95% of consumers should ever need.
"""
from __future__ import annotations

import base64
import copy
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Mapping, Protocol

import httpx

from sigill_sdk import _pdf
from sigill_sdk._canonical import compute_envelope_hash, hash_bytes
from sigill_sdk._envelope import (
    AiEvidenceEnvelopeInput,
    SealedAiEvidenceEnvelope,
)
from sigill_sdk._errors import (
    HashMismatch,
    InvalidProof,
    PdfUnsupported,
    TimestampUnavailable,
)
from sigill_sdk._tsr import parse_tsr
from sigill_sdk._verify import (
    AiEvidenceVerificationResult,
    CadesVerifyResult,
    JadesVerifyResult,
    PqcVerifyInfo,
    VerificationIssue,
    VerificationIssueKind,
)


DEFAULT_BASE_URL = "https://api.sigill.ai"


def _map_detached_verify(node: dict) -> dict:
    """Shared field extraction for the CAdES and JAdES branches of
    /seal/verify-hash — the two verifiers report the same dimensions."""
    cert = node.get("certificate") or {}
    ts   = node.get("timestamp") or {}
    hash_match      = bool(node.get("hashMatch", False))
    signature_valid = bool(node.get("signatureValid", False))
    error           = node.get("error")
    qual_src        = ts.get("qualificationSource", "none")

    post_quantum = None
    pq = node.get("postQuantum") or {}
    if pq.get("present"):
        post_quantum = PqcVerifyInfo(
            present         = True,
            valid           = bool(pq.get("valid", False)),
            signature_valid = bool(pq.get("signatureValid", False)),
            content_bound   = pq.get("contentBound", "not_checked"),
            trusted         = pq.get("trusted", "not_evaluated"),
            algorithm       = pq.get("algorithm", "ml-dsa-87"),
        )

    return {
        "is_valid":        hash_match and signature_valid and error is None,
        "hash_match":      hash_match,
        "signature_valid": signature_valid,
        "signer":          cert.get("subject"),
        "trust":           cert.get("trust"),
        "tsa_name":        ts.get("tsaName"),
        "gen_time":        ts.get("genTime"),
        "qualified":       qual_src not in (None, "none"),
        "error":           error,
        "warnings":        list(node.get("warnings") or []),
        "post_quantum":    post_quantum,
    }


@dataclass(frozen=True)
class PadesSealResult:
    """Result of a delegated PAdES seal — seal_pades().

    The input PDF's bytes never left the machine — only the ByteRange digest
    was transmitted.

    Post-quantum hybrid sealing is deliberately absent here: the PAdES baseline
    profile (ETSI EN 319 142-1) allows a single SignerInfo in the embedded CMS,
    so the ML-DSA-87 hybrid stays on the detached CAdES/JAdES formats until an
    ETSI PQC PAdES profile exists.
    """

    sealed_pdf: bytes
    """The sealed PDF: the original plus the appended signature revision(s)."""

    operation_id: str
    """UUID of the seal operation as recorded in the Sigill dashboard."""

    format: str
    """'pades-bes' | 'pades-b-t' | 'pades-b-lt' | 'pades-b-lta'."""

    timestamped_by: str | None
    """Name of the TSA that timestamped the signature, or None."""

    qualified: bool
    """True when an eIDAS-qualified TSA produced the signature timestamp."""


class ISigillAiEvidenceClient(Protocol):
    """The contract; the concrete SigillClient implements it.

    Mirrors the C# ISigillAiEvidenceClient interface from the spec."""

    def seal(
        self,
        envelope: AiEvidenceEnvelopeInput,
        external_payloads: Mapping[str, bytes] | None = None,
        *,
        tsa_slug: str = "auto",
        qualified: bool = False,
    ) -> SealedAiEvidenceEnvelope: ...

    def seal_cades(
        self,
        data: bytes,
        certificate_id: str,
        *,
        label: str | None = None,
        qualified: bool = False,
        pqc: bool = False,
    ) -> bytes: ...

    def seal_jades(
        self,
        data: bytes,
        certificate_id: str,
        *,
        label: str | None = None,
        qualified: bool = False,
        pqc: bool = False,
        content_type: str | None = None,
    ) -> bytes: ...

    def verify_jades(
        self,
        data: bytes,
        jades: bytes,
        *,
        tsr: bytes | None = None,
    ) -> JadesVerifyResult: ...

    def seal_pades(
        self,
        pdf: bytes,
        certificate_id: str,
        *,
        label: str | None = None,
        qualified: bool = False,
        ltv: bool = True,
        allow_upload_fallback: bool = False,
        reason: str | None = None,
        location: str | None = None,
    ) -> PadesSealResult: ...

    def verify_cades(
        self,
        data: bytes,
        p7s: bytes,
        *,
        tsr: bytes | None = None,
    ) -> CadesVerifyResult: ...

    def verify(
        self,
        envelope: SealedAiEvidenceEnvelope,
        external_payloads: Mapping[str, bytes] | None = None,
    ) -> AiEvidenceVerificationResult: ...


class SigillClient:
    """Concrete implementation of ISigillAiEvidenceClient.

    Construct once per process; the underlying httpx client is reusable.
    """

    def __init__(
        self,
        api_key: str,
        *,
        base_url: str = DEFAULT_BASE_URL,
        timeout: float = 30.0,
        http_client: httpx.Client | None = None,
    ) -> None:
        self._base_url = base_url.rstrip("/")
        self._http = http_client or httpx.Client(
            base_url=self._base_url,
            headers={"Authorization": f"Bearer {api_key}"},
            timeout=timeout,
        )
        self._owns_http = http_client is None

    # ------------------------------------------------------------------ seal

    def seal(
        self,
        envelope: AiEvidenceEnvelopeInput,
        external_payloads: Mapping[str, bytes] | None = None,
        *,
        tsa_slug: str = "auto",
        qualified: bool = False,
        label: str | None = None,
    ) -> SealedAiEvidenceEnvelope:
        """Seal an envelope: populate hash refs, hash the canonical form, attach a proof.

        :param envelope: an AiEvidenceEnvelopeV1-shaped dict produced by EnvelopeBuilder
            or assembled by hand. Will not be mutated.
        :param external_payloads: bytes for any payloadRef whose ``hash`` is not already
            populated. Keyed by the ``ref`` value. Bytes ARE hashed and the hash is
            written into the envelope before sealing.
        :param tsa_slug: which TSA to use. Defaults to ``"auto"`` (round-robin with
            failover, recommended). Passing a specific slug pins it.
        :param qualified: request an eIDAS-qualified timestamp instead of a standard one.
        :param label: human-readable label shown in the Sigill dashboard. Defaults to
            ``activity.name`` from the envelope when not supplied.
        """
        env = copy.deepcopy(envelope)
        external_payloads = external_payloads or {}

        # 1. Populate hashes for any payload refs whose bytes were supplied.
        self._populate_payload_hashes(env, external_payloads)

        # 2. Set integrity.canonicalization (required before computing the hash).
        env.setdefault("integrity", {})
        env["integrity"]["canonicalization"] = "RFC8785"
        # Ensure envelopeHash is absent before computing — defensive.
        env["integrity"].pop("envelopeHash", None)
        env.pop("proofs", None)

        # 3. Canonicalize and compute the envelope hash.
        digest_hex, canonical_bytes = compute_envelope_hash(env, alg="SHA-256")
        env["integrity"]["envelopeHash"] = {
            "alg": "SHA-256",
            "hex": digest_hex,
        }

        # 4. Stamp the envelope hash via Sigill /tsa/stamp-hash. Only the SHA-256 digest
        # leaves the machine — the canonical bytes never do. RFC 3161 compliant.
        # If every TSA in the rotation fails, Sigill returns 502 and we raise
        # TimestampUnavailable. The envelope hash is already correct in `env`, so a
        # caller that catches the exception still has access to the unsealed envelope
        # (via the original input) and can decide whether to retry, fall back, or
        # persist unsealed and seal asynchronously later.
        resolved_label = label if label is not None else (
            envelope.get("activity", {}).get("name")
        )
        proof = self._stamp(digest_hex, tsa_slug=tsa_slug, qualified=qualified, label=resolved_label)
        env["proofs"] = [proof]
        return env

    # ------------------------------------------------------------- seal_cades

    def seal_cades(
        self,
        data: bytes,
        certificate_id: str,
        *,
        label: str | None = None,
        qualified: bool = False,
        pqc: bool = False,
    ) -> bytes:
        """CAdES-seal arbitrary data via /seal/sign-hash.

        Only digests are transmitted — the original document never leaves the
        machine. Returns the raw DER-encoded detached CAdES signature (.p7s bytes).

        :param data: the document bytes to seal.
        :param certificate_id: UUID of the active seal certificate.
        :param label: human-readable label shown in the Sigill dashboard.
        :param qualified: request a qualified timestamp on the signature.
        :param pqc: also add a post-quantum ML-DSA-87 (FIPS 204) signer in the same
            CMS — one .p7s, both signers independently verifiable. The SHA-512 digest
            is computed locally and sent as the ML-DSA signer's messageDigest; content
            still never leaves the machine. Requires a platform PQC cert server-side.
        :raises httpx.HTTPStatusError: for 4xx/5xx API errors.
        """
        hash_hex = hash_bytes(data, alg="SHA-256")
        body: dict = {
            "hashHex": hash_hex,
            "certificateId": str(certificate_id),
            "qualified": qualified,
        }
        if label is not None:
            body["label"] = label
        if pqc:
            body["pqc"] = True
            body["hashHex512"] = hash_bytes(data, alg="SHA-512")
        resp = self._http.post("/seal/sign-hash", json=body)
        resp.raise_for_status()
        return resp.content

    # ------------------------------------------------------------- seal_jades

    def seal_jades(
        self,
        data: bytes,
        certificate_id: str,
        *,
        label: str | None = None,
        qualified: bool = False,
        pqc: bool = False,
        content_type: str | None = None,
    ) -> bytes:
        """JAdES-seal data via /seal/sign-hash with ``format: "jades"``.

        The ETSI signature format for JSON (TS 119 182-1) — the natural fit for
        JSON/JSONL content such as AI evidence and agent logs. Only digests are
        transmitted; returns the detached ``.jades.json`` artifact bytes. The
        seal covers the exact bytes — re-serializing the JSON breaks it by design.

        :param data: the exact bytes to seal (e.g. a canonicalized envelope).
        :param certificate_id: UUID of the active seal certificate.
        :param label: human-readable label shown in the Sigill dashboard.
        :param qualified: request a qualified timestamp on the signature.
        :param pqc: also add a post-quantum ML-DSA-87 signer as a second JWS
            ``signatures[]`` entry (RFC 9964) — same hybrid model as CAdES.
        :param content_type: MIME type recorded in the JAdES sigD, e.g.
            ``application/json``.
        :raises httpx.HTTPStatusError: for 4xx/5xx API errors.
        """
        body: dict = {
            "hashHex": hash_bytes(data, alg="SHA-256"),
            "certificateId": str(certificate_id),
            "qualified": qualified,
            "format": "jades",
        }
        if label is not None:
            body["label"] = label
        if content_type is not None:
            body["contentType"] = content_type
        if pqc:
            body["pqc"] = True
            body["hashHex512"] = hash_bytes(data, alg="SHA-512")
        resp = self._http.post("/seal/sign-hash", json=body)
        resp.raise_for_status()
        return resp.content

    # ----------------------------------------------------------- verify_jades

    def verify_jades(
        self,
        data: bytes,
        jades: bytes,
        *,
        tsr: bytes | None = None,
    ) -> JadesVerifyResult:
        """Verify a detached JAdES signature via POST /seal/verify-hash.

        Hash-only: the original content never leaves the machine. The endpoint
        routes on the artifact bytes (JSON text → JAdES, DER → CAdES); the
        ``p7sBase64`` field doubles as the artifact carrier.

        :param data: the original bytes that were sealed.
        :param jades: the detached JAdES artifact bytes (.jades.json).
        :param tsr: optional standalone RFC 3161 timestamp response bytes (.tsr).
        :raises httpx.HTTPStatusError: for 4xx/5xx API errors.
        """
        import base64
        body_json: dict = {
            "hashHex":   hash_bytes(data, alg="SHA-256"),
            "hashHex512": hash_bytes(data, alg="SHA-512"),
            "p7sBase64": base64.b64encode(jades).decode(),
        }
        if tsr is not None:
            body_json["tsrBase64"] = base64.b64encode(tsr).decode()
        resp = self._http.post("/seal/verify-hash", json=body_json)
        resp.raise_for_status()
        return JadesVerifyResult(**_map_detached_verify(resp.json().get("jades", {})))

    # ------------------------------------------------------------- seal_pades

    def seal_pades(
        self,
        pdf: bytes,
        certificate_id: str,
        *,
        label: str | None = None,
        qualified: bool = False,
        ltv: bool = True,
        allow_upload_fallback: bool = False,
        reason: str | None = None,
        location: str | None = None,
    ) -> PadesSealResult:
        """PAdES-seal a PDF via /seal/sign-pades-hash — delegated, hash-only.

        The signature revision (placeholder /Contents slot, ByteRange) is
        assembled locally by the incremental signer; only ByteRange digests are
        ever transmitted — the PDF itself never leaves the machine. The CMS is
        built server-side and embedded here.

        :param pdf: the PDF bytes to seal. Never mutated; never transmitted
            unless ``allow_upload_fallback`` triggers.
        :param certificate_id: UUID of the active seal certificate.
        :param label: human-readable label shown in the Sigill dashboard.
        :param qualified: use an eIDAS-qualified TSA for all timestamps in the seal.
        :param ltv: upgrade to PAdES B-LT / B-LTA when the server returns LTV
            material: embeds a Document Security Store (chain + OCSP) and a
            DocTimeStamp obtained via /tsa/stamp-hash. Note the DocTimeStamp
            consumes one timestamp from the tenant quota.
        :param allow_upload_fallback: when the local parser cannot handle this
            PDF's structure, upload it to POST /seal/sign and seal server-side
            (identical PAdES output, but the PDF is transmitted to Sigill).
            Default False: the hash-only privacy guarantee is absolute and such
            PDFs raise :class:`PdfUnsupported` instead — leave it off under a
            strict data-residency policy.
        :param reason: written into the PDF signature dictionary's /Reason field.
        :param location: written into the PDF signature dictionary's /Location field.
        :raises PdfUnsupported: when the local parser cannot handle this PDF's
            structure and ``allow_upload_fallback`` is False — nothing has been
            transmitted.
        :raises httpx.HTTPStatusError: for 4xx/5xx API errors.
        """
        # 1. Assemble the signature revision locally: placeholder /Contents slot,
        # ByteRange, and the digests over the signed ranges. Only these digests
        # are ever transmitted.
        try:
            prep = _pdf.prepare(pdf, datetime.now(timezone.utc), reason, location)
        except ValueError as e:
            if not allow_upload_fallback:
                raise PdfUnsupported(str(e)) from e
            # Explicit opt-in: server-side sealing with the full parser. This is
            # the one code path in the SDK that transmits the PDF itself.
            return self._seal_pades_by_upload(
                pdf, certificate_id, label=label, qualified=qualified,
                reason=reason, location=location)

        # 2. hash → Sigill → CMS (+ LTV material for the DSS).
        body: dict = {
            "hashHex": prep.document_hash.hex(),
            "certificateId": str(certificate_id),
            "qualified": qualified,
        }
        if label is not None:
            body["label"] = label
        resp = self._http.post("/seal/sign-pades-hash", json=body)
        resp.raise_for_status()
        data = resp.json()

        cms = base64.b64decode(data["cmsBase64"])
        operation_id = data["operationId"]
        timestamped_by = data.get("timestampedBy")
        qualified_out = bool(data.get("qualified", False))
        cert_ders = [base64.b64decode(x) for x in (data.get("certChainDers") or [])]
        ocsp_ders = [base64.b64decode(x) for x in (data.get("ocspDers") or [])]

        # 3. Embed the CMS into the reserved slot.
        signed_pdf = _pdf.embed(prep, cms)

        # 4. Optional LTV: DSS (B-LT) + DocTimeStamp (B-LTA), both assembled
        # locally. Mirrors the server-side /seal/sign pipeline: the DocTimeStamp
        # is best-effort — a timestamp failure leaves a valid B-LT PDF.
        has_dss = has_doc_ts = False
        if ltv and (cert_ders or ocsp_ders):
            signed_pdf = _pdf.append_dss(signed_pdf, cert_ders, ocsp_ders, cms)
            has_dss = True

            try:
                dt_prep = _pdf.prepare_doc_timestamp(signed_pdf, datetime.now(timezone.utc))
                stamp_body: dict = {
                    "tsaSlug": "auto",
                    "hashHex": dt_prep.document_hash.hex(),
                    "qualified": qualified,
                }
                if label is not None:
                    stamp_body["label"] = label
                dt_resp = self._http.post("/tsa/stamp-hash", json=stamp_body)
                dt_resp.raise_for_status()
                token = base64.b64decode(dt_resp.json()["tokenBase64"])

                signed_pdf = _pdf.embed_doc_timestamp(dt_prep, token)
                has_doc_ts = True
            except Exception:
                # B-LT is still a valid, LTV-enabled seal; the archival timestamp
                # can be added later by re-sealing or via the server-side path.
                pass

        # Same format ladder as the server-side /seal/sign PDF branch.
        if timestamped_by is None:
            fmt = "pades-bes"
        elif not has_dss:
            fmt = "pades-b-t"
        elif not has_doc_ts:
            fmt = "pades-b-lt"
        else:
            fmt = "pades-b-lta"

        return PadesSealResult(
            sealed_pdf=signed_pdf,
            operation_id=operation_id,
            format=fmt,
            timestamped_by=timestamped_by,
            qualified=qualified_out,
        )

    def _seal_pades_by_upload(
        self,
        pdf: bytes,
        certificate_id: str,
        *,
        label: str | None,
        qualified: bool,
        reason: str | None,
        location: str | None,
    ) -> PadesSealResult:
        """Upload fallback (opt-in via ``allow_upload_fallback``): server-side
        PAdES sealing through POST /seal/sign. Same output levels as the
        delegated path; the server handles DSS + DocTimeStamp."""
        data: dict = {"certificateId": str(certificate_id), "qualified": "true" if qualified else "false"}
        if label is not None:
            data["label"] = label
        if reason is not None:
            data["reason"] = reason
        if location is not None:
            data["location"] = location
        resp = self._http.post(
            "/seal/sign",
            data=data,
            files={"file": (label or "document.pdf", pdf, "application/pdf")},
        )
        resp.raise_for_status()

        tsa = resp.headers.get("X-Seal-Timestamped-By")
        return PadesSealResult(
            sealed_pdf=resp.content,
            operation_id=resp.headers.get("X-Seal-Operation-Id", ""),
            format=resp.headers.get("X-Seal-Format", "pades-bes"),
            timestamped_by=None if tsa in (None, "none") else tsa,
            qualified=resp.headers.get("X-Seal-Qualified", "").lower() == "true",
        )

    # ---------------------------------------------------------- verify_cades

    def verify_cades(
        self,
        data: bytes,
        p7s: bytes,
        *,
        tsr: bytes | None = None,
    ) -> CadesVerifyResult:
        """Verify a detached CAdES signature via POST /seal/verify.

        Sends the original document and .p7s to the Sigill API for server-side
        verification. The endpoint is public — no API key is required — but the
        existing HTTP client (with auth header) works fine against it.

        :param data: the original document bytes that were sealed.
        :param p7s: the detached CAdES signature bytes (.p7s).
        :param tsr: optional standalone RFC 3161 timestamp response bytes (.tsr).
        :raises httpx.HTTPStatusError: for 4xx/5xx API errors.
        """
        import base64
        body_json: dict = {
            "hashHex":   hash_bytes(data, alg="SHA-256"),
            # Always supply SHA-512 so a hybrid seal's ML-DSA content binding is
            # actually checked (content_bound 'yes'/'no' rather than 'not_checked').
            # Ignored by the server for classical-only seals.
            "hashHex512": hash_bytes(data, alg="SHA-512"),
            "p7sBase64": base64.b64encode(p7s).decode(),
        }
        if tsr is not None:
            body_json["tsrBase64"] = base64.b64encode(tsr).decode()
        resp = self._http.post("/seal/verify-hash", json=body_json)
        resp.raise_for_status()
        return CadesVerifyResult(**_map_detached_verify(resp.json().get("cades", {})))

    # ---------------------------------------------------------------- verify

    def verify(
        self,
        envelope: SealedAiEvidenceEnvelope,
        external_payloads: Mapping[str, bytes] | None = None,
    ) -> AiEvidenceVerificationResult:
        """Verify a sealed envelope. Collects all issues — does not short-circuit.

        Returns an AiEvidenceVerificationResult. ``result.is_valid`` is True iff the
        envelope hash recomputes correctly, every supplied/required external payload
        matches its registered hash, and at least one proof parses with a matching
        message imprint.
        """
        external_payloads = external_payloads or {}
        result = AiEvidenceVerificationResult(is_valid=True)

        # 1. Recompute envelope hash and compare to integrity.envelopeHash.
        registered = (
            envelope.get("integrity", {}).get("envelopeHash") if isinstance(envelope, dict) else None
        )
        try:
            computed_hex, _ = compute_envelope_hash(envelope, alg=(registered or {}).get("alg", "SHA-256"))
            result.envelope_hash_hex = computed_hex
        except Exception as e:
            result.add_issue(
                VerificationIssue(
                    kind=VerificationIssueKind.CANONICALIZATION_FAILED,
                    target="envelope",
                    message=f"Cannot canonicalize envelope: {e}",
                )
            )
            return result  # nothing else makes sense without a hash

        if not registered or "hex" not in registered:
            result.add_issue(
                VerificationIssue(
                    kind=VerificationIssueKind.HASH_MISMATCH,
                    target="envelope",
                    message="Envelope has no integrity.envelopeHash",
                )
            )
        elif registered["hex"] != computed_hex:
            result.add_issue(
                VerificationIssue(
                    kind=VerificationIssueKind.HASH_MISMATCH,
                    target="envelope",
                    message="envelope_hash_does_not_match: envelope content has been modified",
                    expected=registered["hex"],
                    actual=computed_hex,
                )
            )

        # 2. Walk payload refs and check each against external_payloads.
        for path, ref_node in self._iter_payload_refs(envelope):
            if "hash" not in ref_node:  # inline-only refs are checked by the canonical hash
                continue
            ref_id = ref_node.get("ref")
            if not ref_id:
                # malformed envelope — should not happen if produced by this SDK
                result.add_issue(
                    VerificationIssue(
                        kind=VerificationIssueKind.HASH_MISMATCH,
                        target=path,
                        message="payloadRef has 'hash' but no 'ref'; cannot resolve external bytes",
                    )
                )
                continue
            if ref_id not in external_payloads:
                result.add_issue(
                    VerificationIssue(
                        kind=VerificationIssueKind.HASH_MISMATCH,
                        target=ref_id,
                        message=f"payload_not_supplied: external bytes for ref {ref_id!r} were not provided to verify()",
                        expected=ref_node["hash"]["hex"],
                    )
                )
                continue
            actual_hex = hash_bytes(
                external_payloads[ref_id], alg=ref_node["hash"].get("alg", "SHA-256")
            )
            if actual_hex != ref_node["hash"]["hex"]:
                result.add_issue(
                    VerificationIssue(
                        kind=VerificationIssueKind.HASH_MISMATCH,
                        target=ref_id,
                        message=f"digest_does_not_match: supplied bytes for ref {ref_id!r} hash to a different value",
                        expected=ref_node["hash"]["hex"],
                        actual=actual_hex,
                    )
                )

        # 3. Walk proofs and verify each. Re-canonicalize so we can recompute the message
        # imprint with whatever hash algorithm the TSA used (Sigill auto-mode hashes the
        # request with SHA-512 even when the envelope hash itself is SHA-256).
        _, canonical_bytes = compute_envelope_hash(envelope, alg=(registered or {}).get("alg", "SHA-256"))
        proofs = envelope.get("proofs", []) if isinstance(envelope, dict) else []
        if not proofs:
            result.add_issue(
                VerificationIssue(
                    kind=VerificationIssueKind.TIMESTAMP_UNAVAILABLE,
                    target="proofs",
                    message="Envelope has no proofs[]; was sealed without a timestamp.",
                )
            )
        for i, proof in enumerate(proofs):
            self._verify_proof(proof, result, i, canonical_bytes)

        return result

    # ------------------------------------------------------------ internals

    def _populate_payload_hashes(
        self, env: dict, external_payloads: Mapping[str, bytes]
    ) -> None:
        """Fill in payloadRef.hash for any ref whose bytes the caller supplied.

        If hash is already present and the bytes are also supplied, verify they match
        and raise HashMismatch on disagreement (producer-time strictness). If hash is
        absent but bytes are also not supplied, leave the ref alone — verification
        will catch this case.
        """
        for path, ref_node in self._iter_payload_refs(env):
            if "inline" in ref_node:
                continue
            ref_id = ref_node.get("ref")
            if not ref_id or ref_id not in external_payloads:
                continue
            data = external_payloads[ref_id]
            alg = ref_node.get("hash", {}).get("alg", "SHA-256")
            actual = hash_bytes(data, alg=alg)
            if "hash" in ref_node and ref_node["hash"].get("hex") not in (None, "", actual):
                raise HashMismatch(
                    f"Pre-declared hash for ref {ref_id!r} ({ref_node['hash']['hex']}) "
                    f"does not match supplied bytes ({actual})"
                )
            ref_node["hash"] = {"alg": alg, "hex": actual, "sizeBytes": len(data)}

    @staticmethod
    def _iter_payload_refs(env):
        """Yield (path, node) for every dict that looks like a payloadRef."""
        # A payloadRef has either inline or hash, plus optional ref/contentType/encoding.
        # We identify them by the presence of one of inline/hash/ref while also being a dict.
        def looks_like_ref(d: dict) -> bool:
            if not isinstance(d, dict):
                return False
            return any(k in d for k in ("inline", "hash", "ref")) and any(
                k in d for k in ("contentType", "encoding", "ref", "hash", "inline")
            )

        # Top-level slots known to hold payloadRefs:
        for key in ("prompt", "output"):
            node = env.get(key)
            if looks_like_ref(node):
                yield key, node
        for arr_key in ("inputs", "retrievedContext", "outputArtifacts"):
            for i, item in enumerate(env.get(arr_key, []) or []):
                if looks_like_ref(item):
                    yield f"{arr_key}[{i}]", item

    def _verify_proof(self, proof, result, index, canonical_bytes: bytes):
        """Verify a single proof entry against the envelope's canonical bytes.

        For RFC 3161 proofs: parse the TSR, then check that the TSA's message-imprint
        equals SHA-x(canonical_bytes) where SHA-x is whichever algorithm the TSR used.
        """
        target = f"proofs[{index}]"
        if not isinstance(proof, dict):
            result.add_issue(
                VerificationIssue(
                    kind=VerificationIssueKind.INVALID_PROOF,
                    target=target,
                    message="proof is not an object",
                )
            )
            return
        if proof.get("type") != "rfc3161":
            result.add_issue(
                VerificationIssue(
                    kind=VerificationIssueKind.INVALID_PROOF,
                    target=target,
                    message=f"unsupported proof type {proof.get('type')!r}; v1 supports 'rfc3161'",
                )
            )
            return
        try:
            parsed = parse_tsr(proof["tsrBase64"])
        except InvalidProof as e:
            result.add_issue(
                VerificationIssue(
                    kind=VerificationIssueKind.INVALID_PROOF,
                    target=target,
                    message=str(e),
                )
            )
            return

        # The TSA's message-imprint is over the bytes we submitted to /tsa/stamp, which
        # were the canonical envelope bytes. Recompute and compare.
        if parsed.hash_alg in ("SHA-256", "SHA-384", "SHA-512"):
            expected_imprint = hash_bytes(canonical_bytes, alg=parsed.hash_alg)
            if parsed.hashed_message_hex != expected_imprint:
                result.add_issue(
                    VerificationIssue(
                        kind=VerificationIssueKind.INVALID_PROOF,
                        target=target,
                        message="TSR message-imprint does not match envelope canonical bytes",
                        expected=expected_imprint,
                        actual=parsed.hashed_message_hex,
                    )
                )
        else:
            result.add_issue(
                VerificationIssue(
                    kind=VerificationIssueKind.INVALID_PROOF,
                    target=target,
                    message=f"TSR uses unsupported hash algorithm {parsed.hash_alg!r} (OID {parsed.hash_alg_oid})",
                )
            )

        result.timestamps.append(
            {
                "tsa_name": parsed.tsa_name,
                "gen_time": parsed.gen_time.isoformat(),
                "serial": parsed.serial,
                "hash_alg": parsed.hash_alg,
                "hashed_message_hex": parsed.hashed_message_hex,
                "qualified": bool(proof.get("qualified", False)),
                "policy_oid": parsed.policy_oid,
            }
        )

    def _stamp(self, hash_hex: str, *, tsa_slug: str, qualified: bool, label: str | None):
        """Call Sigill /tsa/stamp-hash with the SHA-256 hex digest of the canonical envelope.

        Only the digest is transmitted — the envelope never leaves the machine.
        Returns a proof dict shaped per spec §5. Raises TimestampUnavailable if
        Sigill reports all TSAs failed.
        """
        body: dict = {
            "tsaSlug": tsa_slug,
            "hashHex": hash_hex,
            "qualified": qualified,
        }
        if label is not None:
            body["label"] = label
        resp = self._http.post("/tsa/stamp-hash", json=body)
        if resp.status_code == 502:
            try:
                payload = resp.json()
            except Exception:
                payload = {}
            raise TimestampUnavailable(
                payload.get("message", "All enabled TSAs failed."),
                failures=payload.get("failures", []),
                attempts=payload.get("attemptsTried", 0),
            )
        resp.raise_for_status()
        data = resp.json()
        proof = {
            "type": "rfc3161",
            "tsrBase64": data["tsrBase64"],
            "tsaName": data.get("tsaName"),
            "genTime": data.get("genTime"),
            "serial": data.get("serial"),
            "qualified": bool(data.get("qualified", False)),
        }
        if data.get("policyOid"):
            proof["policyOid"] = data["policyOid"]
        return proof

    # context manager so callers can `with SigillClient(...) as c:`
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def close(self) -> None:
        if self._owns_http:
            self._http.close()

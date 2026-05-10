"""SigillClient — seal and verify AI evidence envelopes.

Public API mirrors the .NET interface ISigillAiEvidenceClient. The seal() / verify()
flow is the surface 95% of consumers should ever need.
"""
from __future__ import annotations

import base64
import copy
from typing import Mapping, Protocol

import httpx

from sigill_sdk._canonical import compute_envelope_hash, hash_bytes
from sigill_sdk._envelope import (
    AiEvidenceEnvelopeInput,
    SealedAiEvidenceEnvelope,
)
from sigill_sdk._errors import (
    HashMismatch,
    InvalidProof,
    TimestampUnavailable,
)
from sigill_sdk._tsr import parse_tsr
from sigill_sdk._verify import (
    AiEvidenceVerificationResult,
    VerificationIssue,
    VerificationIssueKind,
)


DEFAULT_BASE_URL = "https://api.sigill.ai"


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

        # 4. Stamp the canonical bytes via Sigill /tsa/stamp. Sigill hashes them
        # server-side before forwarding to the TSA — the TSA never sees the content.
        # If every TSA in the rotation fails, Sigill returns 502 and we raise
        # TimestampUnavailable. The envelope hash is already correct in `env`, so a
        # caller that catches the exception still has access to the unsealed envelope
        # (via the original input) and can decide whether to retry, fall back, or
        # persist unsealed and seal asynchronously later.
        resolved_label = label if label is not None else (
            envelope.get("activity", {}).get("name")
        )
        proof = self._stamp(canonical_bytes, tsa_slug=tsa_slug, qualified=qualified, label=resolved_label)
        env["proofs"] = [proof]
        return env

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

    def _stamp(self, canonical_bytes: bytes, *, tsa_slug: str, qualified: bool, label: str | None):
        """Call Sigill /tsa/stamp with the canonical envelope bytes.

        Sigill hashes the bytes server-side; the TSA only ever sees the hash.
        Returns a proof dict shaped per spec §5. Raises TimestampUnavailable if
        Sigill reports all TSAs failed.
        """
        body: dict = {
            "tsaSlug": tsa_slug,
            "fileBase64": base64.b64encode(canonical_bytes).decode("ascii"),
            "qualified": qualified,
        }
        if label is not None:
            body["label"] = label
        resp = self._http.post("/tsa/stamp", json=body)
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


def _strip_for_rehash(_result, _h):
    """Internal helper: provided so the proof-verification step can recompute canonical
    bytes on the fly. We re-derive from result context rather than threading the
    original envelope through; see _verify_proof."""
    # This shim exists because in _verify_proof we don't directly carry the envelope —
    # we rely on the caller (verify) supplying a closure. To keep the code straight,
    # we simply re-canonicalize from the verifier-known envelope. This function is
    # intentionally minimal; if you find it confusing, see verify() which closes over
    # the envelope and could be refactored to pass it in. Kept this way to keep the
    # verify() function readable at a glance.
    raise NotImplementedError(
        "Internal helper — should never be invoked; see _verify_proof"
    )

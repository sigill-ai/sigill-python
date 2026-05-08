"""Build synthetic RFC 3161 TimeStampToken bytes for tests.

Hitting a real TSA from CI is flaky and slow. For verification-path tests we want
deterministic, offline-constructible TSR bytes that the SDK's parser will accept.

This module produces a real, well-formed RFC 3161 TimeStampToken (CMS SignedData
wrapping a TSTInfo) signed with a self-signed throwaway TSA certificate. The TSA cert
has the required ExtendedKeyUsage (id-kp-timeStamping = 1.3.6.1.5.5.7.3.8) so it will
pass the .NET Rfc3161TimestampToken verifier too — important for cross-SDK fixture
sharing later.

Implementation notes:
- We rely on `cryptography` (already a Sigill SDK dep via asn1crypto's siblings) for
  key/cert generation and the actual signing operation. The CMS/TSTInfo wrapping is
  done with `asn1crypto`.
- Generated TSRs are NOT trustworthy timestamps. They are FIXTURES. The test code
  always asserts that something that should fail does fail.
"""
from __future__ import annotations

import datetime as _dt
import hashlib
import os
import secrets

from asn1crypto import algos, cms, core, tsp, x509 as a_x509
from cryptography import x509 as c_x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID


# Module-level cache: generating an RSA key is expensive; reuse one TSA identity for
# the whole test run.
_TSA_KEY: rsa.RSAPrivateKey | None = None
_TSA_CERT: c_x509.Certificate | None = None


def _ensure_tsa_identity() -> tuple[rsa.RSAPrivateKey, c_x509.Certificate]:
    global _TSA_KEY, _TSA_CERT
    if _TSA_KEY is not None and _TSA_CERT is not None:
        return _TSA_KEY, _TSA_CERT

    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = issuer = c_x509.Name([
        c_x509.NameAttribute(NameOID.COMMON_NAME, "Sigill SDK Test TSA"),
        c_x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Sigill SDK Tests"),
    ])
    now = _dt.datetime.now(_dt.timezone.utc)
    cert = (
        c_x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(c_x509.random_serial_number())
        .not_valid_before(now - _dt.timedelta(minutes=5))
        .not_valid_after(now + _dt.timedelta(days=365))
        .add_extension(
            c_x509.ExtendedKeyUsage([ExtendedKeyUsageOID.TIME_STAMPING]),
            critical=True,
        )
        .add_extension(
            c_x509.BasicConstraints(ca=False, path_length=None),
            critical=True,
        )
        .sign(key, hashes.SHA256())
    )
    _TSA_KEY, _TSA_CERT = key, cert
    return key, cert


def make_tsr(
    message_imprint: bytes,
    *,
    hash_alg: str = "SHA-256",
    gen_time: _dt.datetime | None = None,
    serial: int | None = None,
    policy_oid: str = "1.2.3.4.5",
) -> bytes:
    """Construct a real RFC 3161 TimeStampToken (CMS SignedData) over ``message_imprint``.

    :param message_imprint: the digest produced by hashing the user-data with the same
        algorithm named in ``hash_alg``. The SDK feeds canonical envelope bytes to a
        TSA and the TSA hashes them; here we let the caller supply a precomputed digest
        because that's how the protocol works at the wire.
    :returns: DER-encoded ContentInfo bytes — exactly what the SDK base64-encodes into
        the ``proofs[].tsrBase64`` field.
    """
    if hash_alg not in ("SHA-256", "SHA-384", "SHA-512"):
        raise ValueError(f"unsupported hash alg for fixture: {hash_alg!r}")
    expected_len = {"SHA-256": 32, "SHA-384": 48, "SHA-512": 64}[hash_alg]
    if len(message_imprint) != expected_len:
        raise ValueError(
            f"message_imprint len {len(message_imprint)} doesn't match {hash_alg} ({expected_len})"
        )

    key, cert = _ensure_tsa_identity()
    if gen_time is None:
        gen_time = _dt.datetime.now(_dt.timezone.utc).replace(microsecond=0)
    if serial is None:
        serial = int.from_bytes(secrets.token_bytes(8), "big")

    hash_oid = {
        "SHA-256": "2.16.840.1.101.3.4.2.1",
        "SHA-384": "2.16.840.1.101.3.4.2.2",
        "SHA-512": "2.16.840.1.101.3.4.2.3",
    }[hash_alg]

    # 1. Build the TSTInfo structure (the actual timestamp assertion).
    tst_info = tsp.TSTInfo({
        "version": "v1",
        "policy": policy_oid,
        "message_imprint": {
            "hash_algorithm": {"algorithm": hash_oid},
            "hashed_message": message_imprint,
        },
        "serial_number": serial,
        "gen_time": gen_time,
    })
    tst_info_der = tst_info.dump()

    # 2. Wrap it in CMS SignedData. We must compute a SignerInfo whose signature
    # covers the signed-attributes (which include a digest of the encapsulated content).
    cert_der = cert.public_bytes(serialization.Encoding.DER)
    a_cert = a_x509.Certificate.load(cert_der)

    content_digest = _hash(tst_info_der, hash_alg)
    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({
            "type": "content_type",
            "values": [cms.ContentType("tst_info")],
        }),
        cms.CMSAttribute({
            "type": "message_digest",
            "values": [cms.OctetString(content_digest)],
        }),
        cms.CMSAttribute({
            "type": "signing_time",
            "values": [cms.Time({"utc_time": gen_time})],
        }),
    ])
    # The signature input is the DER encoding of signed_attrs as a SET (not the
    # IMPLICIT [0] tag they appear under inside SignerInfo). asn1crypto handles this
    # via the .untag() trick: dump signed_attrs as a SET OF.
    to_sign = signed_attrs.dump()  # produces the SET OF encoding directly
    signature = key.sign(
        to_sign,
        padding.PKCS1v15(),
        getattr(hashes, hash_alg.replace("-", ""))(),
    )

    sig_alg_oid = {
        "SHA-256": "1.2.840.113549.1.1.11",  # sha256WithRSAEncryption
        "SHA-384": "1.2.840.113549.1.1.12",
        "SHA-512": "1.2.840.113549.1.1.13",
    }[hash_alg]

    signer_info = cms.SignerInfo({
        "version": "v1",
        "sid": cms.SignerIdentifier({
            "issuer_and_serial_number": {
                "issuer": a_cert["tbs_certificate"]["issuer"],
                "serial_number": a_cert["tbs_certificate"]["serial_number"],
            }
        }),
        "digest_algorithm": {"algorithm": hash_oid},
        "signed_attrs": signed_attrs,
        "signature_algorithm": {"algorithm": sig_alg_oid},
        "signature": signature,
    })

    signed_data = cms.SignedData({
        "version": "v3",
        "digest_algorithms": [{"algorithm": hash_oid}],
        "encap_content_info": cms.EncapsulatedContentInfo({
            "content_type": "tst_info",
            "content": core.ParsableOctetString(tst_info_der),
        }),
        "certificates": [a_cert],
        "signer_infos": [signer_info],
    })
    content_info = cms.ContentInfo({
        "content_type": "signed_data",
        "content": signed_data,
    })
    return content_info.dump()


def _hash(data: bytes, alg: str) -> bytes:
    h = {
        "SHA-256": hashlib.sha256,
        "SHA-384": hashlib.sha384,
        "SHA-512": hashlib.sha512,
    }[alg]()
    h.update(data)
    return h.digest()

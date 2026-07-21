"""Cross-repo golden vectors for the PDF incremental signer.

``_pdf.py`` is a port of the platform signer, and delegated PAdES sealing
depends on all implementations producing byte-identical output. The same
constants are pinned in the platform repo (tests/PdfSignerGoldenVectorTests.cs)
and the .NET SDK (tests/Sigill.Sdk.Tests/PdfSignerGoldenVectorTests.cs). A
failure here means the ports have drifted — fix all three repos in the same
change set.
"""
from __future__ import annotations

import hashlib
from datetime import datetime, timezone

from sigill_sdk import _pdf

PDF = (
    "%PDF-1.4\n"
    "1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    "2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n"
    "3 0 obj\n<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>\nendobj\n"
    "xref\n0 4\n0000000000 65535 f \n"
    "trailer\n<< /Size 4 /Root 1 0 R >>\n"
    "startxref\n9\n%%EOF\n"
).encode("ascii")

T1 = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)
T2 = datetime(2026, 1, 2, 3, 4, 6, tzinfo=timezone.utc)


def _pattern(length: int, mod: int) -> bytes:
    return bytes(i % mod for i in range(length))


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def test_signer_output_matches_cross_repo_golden_vectors() -> None:
    cms = _pattern(900, 251)
    cert = _pattern(300, 13)
    ocsp = _pattern(200, 17)
    token = _pattern(400, 23)

    prep = _pdf.prepare(PDF, T1, "Golden", "Vector (X)")
    assert _sha(prep.bytes) == "03ccfbecd8e840624613d05687b0e3a99530593b361d11f6de0461d2eb6fcde5"
    assert prep.document_hash.hex() == "47266535eedf3ff5f91439055ed9048f171279cf6fe2209cc0d4bf0e2ddbb7e2"

    embedded = _pdf.embed(prep, cms)
    assert _sha(embedded) == "fe12166e8359c77615becf76b0be828fa65ef591f5d42b0669f61f6a686b882b"

    dss = _pdf.append_dss(embedded, [cert], [ocsp], cms)
    assert _sha(dss) == "d2d8ac0179883b29edad8d18f3c0ef69db7613c45bfdb878f6acb043097256d3"

    dt = _pdf.prepare_doc_timestamp(dss, T2)
    assert _sha(dt.bytes) == "6756707d60d22f50ee34a3850c5a48bd0f67db9de8adfc41b5ee47d4f79fd913"
    assert dt.document_hash.hex() == "e6270386b20cfe1a67e2c12e7ae99e2f3e1d223844e6870f09fbfad17cea6148"

    final = _pdf.embed_doc_timestamp(dt, token)
    assert _sha(final) == "bd088853743d90d82ee4cdb79aaa1d4fc2f9543ed12078ff0ab58c00c33bdb51"

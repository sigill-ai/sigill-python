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


def _pattern(length: int, mod: int) -> bytes:
    return bytes(i % mod for i in range(length))


def _sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()


def test_signer_output_matches_cross_repo_golden_vectors() -> None:
    cms = _pattern(900, 251)
    cert = _pattern(300, 13)
    ocsp = _pattern(200, 17)
    token = _pattern(400, 23)

    prep = _pdf.prepare(PDF, T1, "Golden Vector", "Golden", "Vector (X)")
    assert _sha(prep.bytes) == "b5d39c763dd5a7e9fc24dad7b070e00b9f0c6c40658c714dca99690b54a6b712"
    assert prep.document_hash.hex() == "ff51dc7d56810a178dcbc05a43c1cdb34b4f75a0d50351d47ae19faac6a5c83c"

    embedded = _pdf.embed(prep, cms)
    assert _sha(embedded) == "cf39c8cc8375423558f89d70efd5f490b473297fee6a4c49fc16794b252603f8"

    dss = _pdf.append_dss(embedded, [cert], [ocsp], cms)
    assert _sha(dss) == "4640e64a37264e912f331539751f220ba8ac73ddcfc489adad61060d4b01da87"

    dt = _pdf.prepare_doc_timestamp(dss)
    assert _sha(dt.bytes) == "ac259ce36157a452883e48b63f7e5819c1fa10b7d7e594aa0802772a8150ae74"
    assert dt.document_hash.hex() == "811393190bf59d619c02ae2e69b4a6eda7d63007f1554074875c23e8c3b17b24"

    final = _pdf.embed_doc_timestamp(dt, token)
    assert _sha(final) == "fb4fa1d61ec7a178a005fb9314ecf9650f4a12b111d483be4bf45c507751bdc5"

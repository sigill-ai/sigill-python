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


def test_xref_stream_base_matches_cross_repo_golden_vectors() -> None:
    """Same inputs as above on a base whose cross-reference section is a
    STREAM (PDF 1.5+): every appended revision must be a cross-reference stream
    too, byte-identical across implementations. Pinned with the same constants
    in the .NET SDK (tests/Sigill.Sdk.Tests/PdfSignerXrefStreamTests.cs)."""
    from test_pdf_xref_stream import build_xref_stream_pdf

    pdf = build_xref_stream_pdf()
    cms = _pattern(900, 251)
    assert _sha(pdf) == "f1453825b415c460ef1cc3fb4803c2a6bad0a8fc99cead5f13ed286f889f7ccb"

    prep = _pdf.prepare(pdf, T1, "Golden Vector", "Golden", "Vector (X)")
    assert _sha(prep.bytes) == "7525b1739ee2d3d1684cabef5afda8d4a556fd5923e4a9763ba8e56980e0b75f"
    assert prep.document_hash.hex() == "74f0fbcf173edf47607bc019f343d941f60ad900cc85763bbe1565b45a04500a"

    embedded = _pdf.embed(prep, cms)
    assert _sha(embedded) == "5cb46d3b0d407355f4098b6809d83d10541cc8b5b1cb9c429380ecfa35338825"

    dss = _pdf.append_dss(embedded, [_pattern(300, 13)], [_pattern(200, 17)], cms)
    assert _sha(dss) == "3d48f64fd256131d06597730184d6ff9a8cf5f53c99e01b8be431cf8bfd11736"

    dt = _pdf.prepare_doc_timestamp(dss)
    assert _sha(dt.bytes) == "d8bae000cce77ec1760da90607d1ab2e9e605cc57d83593c65c5512d33f6b4eb"
    assert dt.document_hash.hex() == "01ba2ea5fe8aee72611c068e383bb32996d351685b45db6246a3d3c7f015d257"

    final = _pdf.embed_doc_timestamp(dt, _pattern(400, 23))
    assert _sha(final) == "1f678126c36df68081749989c442021d60868a9812b91670200264f0bf4c3c07"

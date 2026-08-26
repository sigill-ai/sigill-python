"""Regression tests for the page /Annots handling in the PDF signer port.

PowerPoint/Office exporters commonly emit the page's annotation array as an
indirect object (``/Annots 9 0 R``). The signer used to miss that form and
append a SECOND /Annots key to the page dictionary — duplicate dictionary keys
are undefined behaviour per ISO 32000-1 §7.3.7, and a last-wins parser silently
drops every pre-existing annotation from the sealed document.

Mirrors the platform's tests/PdfIncrementalSignerAnnotsTests.cs. The fixture is
assembled programmatically so its xref offsets and startxref are byte-accurate —
a structurally valid PDF, not just signer-parseable text.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone

import pytest

from sigill_sdk import _pdf

T1 = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _build_indirect_annots_pdf() -> bytes:
    """Minimal but structurally valid PDF: correct xref entry offsets, correct
    startxref, one page whose /Annots is an INDIRECT reference to object 5,
    which holds one link annotation (object 4)."""
    out = "%PDF-1.4\n"
    offsets: dict[int, int] = {}

    def obj(obj_id: int, body: str) -> None:
        nonlocal out
        offsets[obj_id] = len(out)
        out += f"{obj_id} 0 obj\n{body}\nendobj\n"

    obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
    obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Annots 5 0 R >>")
    obj(4, "<< /Type /Annot /Subtype /Link /Rect [0 0 10 10] >>")
    obj(5, "[4 0 R]")

    xref_pos = len(out)
    out += "xref\n0 6\n0000000000 65535 f \n"
    for obj_id in range(1, 6):
        out += f"{offsets[obj_id]:010d} 00000 n \n"
    out += "trailer\n<< /Size 6 /Root 1 0 R >>\n"
    out += f"startxref\n{xref_pos}\n%%EOF\n"
    return out.encode("ascii")


def _assert_xref_chain_resolves(text: str) -> None:
    """Follow every xref table in the file and require that every in-use
    entry's offset lands on ``N 0 obj`` for the declared object number."""
    sections = list(re.finditer(r"(?:^|\n)xref\r?\n", text))
    assert sections, "no xref table found"

    for section in sections:
        pos = section.end()
        while True:
            header = re.match(r"(\d+)\s+(\d+)\r?\n", text[pos:])
            if header is None:
                break
            start, count = int(header.group(1)), int(header.group(2))
            pos += header.end()
            for i in range(count):
                entry = text[pos:pos + 20]
                pos += 20
                if entry[17] != "n":  # free entry
                    continue
                off = int(entry[:10])
                expected = f"{start + i} 0 obj"
                assert text[off:off + len(expected)] == expected, (
                    f"xref entry for object {start + i} points at offset {off}, "
                    f"which does not start with {expected!r}")

    # startxref of the LAST revision must point at an xref keyword.
    sx_matches = list(re.finditer(r"startxref\s+(\d+)\s*%%EOF", text))
    assert sx_matches, "trailing startxref not found"
    sx_off = int(sx_matches[-1].group(1))
    assert text[sx_off:sx_off + 4] == "xref"


def test_fixture_is_structurally_valid() -> None:
    _assert_xref_chain_resolves(_build_indirect_annots_pdf().decode("ascii"))


def test_prepare_indirect_annots_patches_array_object_not_page() -> None:
    pdf = _build_indirect_annots_pdf()
    prep = _pdf.prepare(pdf, T1)
    text = prep.bytes.decode("latin-1")
    increment = text[len(pdf):]

    # The array object is re-emitted with the old annot preserved and the new
    # signature widget appended (widget id 7 = max object id 5 + sig 6).
    assert "5 0 obj\n[4 0 R 7 0 R]" in increment

    # The page dictionary is NOT re-emitted, so no duplicate /Annots key can
    # exist: exactly one /Annots across the whole file, still the indirect
    # reference in the original page dict.
    assert len(re.findall(r"/Annots", text)) == 1
    assert len(re.findall(r"/Annots\s+5\s+0\s+R", text)) == 1
    assert "3 0 obj" not in increment

    # Every xref section in the signed output resolves to a real object
    # header at the recorded byte offset.
    _assert_xref_chain_resolves(text)


def test_prepare_sig_dict_carries_signer_name() -> None:
    pdf = _build_indirect_annots_pdf()
    prep = _pdf.prepare(pdf, T1, "Golden Vector")
    increment = prep.bytes.decode("latin-1")[len(pdf):]
    assert "/Name (Golden Vector)" in increment


def test_prepare_without_signer_name_omits_name_key() -> None:
    pdf = _build_indirect_annots_pdf()
    prep = _pdf.prepare(pdf, T1)
    increment = prep.bytes.decode("latin-1")[len(pdf):]
    assert "/Name" not in increment


def test_add_annot_to_page_raises_on_indirect_ref() -> None:
    with pytest.raises(ValueError, match="indirect /Annots"):
        _pdf._add_annot_to_page(
            "<< /Type /Page /Parent 2 0 R /Annots 5 0 R >>", 7)


def test_prepare_doc_timestamp_dict_has_no_m_entry() -> None:
    pdf = _build_indirect_annots_pdf()
    prep = _pdf.prepare(pdf, T1)
    embedded = _pdf.embed(prep, b"\x01\x02\x03")
    dt = _pdf.prepare_doc_timestamp(embedded)

    text = dt.bytes.decode("latin-1")
    increment = text[len(embedded):]
    dt_dict = re.search(r"<< /Type /DocTimeStamp.*?>>", increment, re.DOTALL)
    assert dt_dict is not None
    # EN 319 142-1 §5.4.3: /M should not be present — readers take the time
    # from the token's genTime.
    assert "/M (" not in dt_dict.group(0)

    _assert_xref_chain_resolves(text)

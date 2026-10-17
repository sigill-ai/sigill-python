"""Incremental updates on cross-reference-stream PDFs.

PDF 1.5+ writers commonly replace the classic ``xref`` table with a
cross-reference STREAM (an object ``<< /Type /XRef ... >>`` at ``startxref``).
The signer used to append a classic table to such documents; its trailer's
``/Prev`` then pointed at a cross-reference stream, a mixed chain that strict
readers (Adobe Acrobat among them) refuse to follow — the signature shows as
invalid. Every revision the signer appends must use the base document's format.

The fixtures are assembled programmatically so every offset is byte-accurate.
"""
from __future__ import annotations

import hashlib
import re
from datetime import datetime, timezone

from sigill_sdk import _pdf

T1 = datetime(2026, 1, 2, 3, 4, 5, tzinfo=timezone.utc)


def _pattern(length: int, mod: int) -> bytes:
    return bytes(i % mod for i in range(length))


def build_xref_stream_pdf() -> bytes:
    """Minimal but structurally valid PDF whose only cross-reference section is
    a cross-reference STREAM (object 4) — no classic xref table anywhere."""
    out = bytearray(b"%PDF-1.5\n")
    offsets: dict[int, int] = {}

    def obj(obj_id: int, body: str) -> None:
        offsets[obj_id] = len(out)
        out.extend(f"{obj_id} 0 obj\n{body}\nendobj\n".encode("ascii"))

    obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
    obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")

    xref_pos = len(out)
    # /W [1 4 2]; entries for objects 0..4 (object 4 is this stream itself).
    entries = [(0, 0, 65535), (1, offsets[1], 0), (1, offsets[2], 0),
               (1, offsets[3], 0), (1, xref_pos, 0)]
    data = b"".join(
        bytes([typ]) + off.to_bytes(4, "big") + gen.to_bytes(2, "big")
        for typ, off, gen in entries)
    out.extend(
        f"4 0 obj\n<< /Type /XRef /Size 5 /Root 1 0 R /W [1 4 2] /Index [0 5] "
        f"/Length {len(data)} >>\nstream\n".encode("ascii"))
    out.extend(data)
    out.extend(b"\nendstream\nendobj\n")
    out.extend(f"startxref\n{xref_pos}\n%%EOF\n".encode("ascii"))
    return bytes(out)


def build_classic_pdf() -> bytes:
    out = "%PDF-1.4\n"
    offsets: dict[int, int] = {}

    def obj(obj_id: int, body: str) -> None:
        nonlocal out
        offsets[obj_id] = len(out)
        out += f"{obj_id} 0 obj\n{body}\nendobj\n"

    obj(1, "<< /Type /Catalog /Pages 2 0 R >>")
    obj(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
    obj(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] >>")
    xref_pos = len(out)
    out += "xref\n0 4\n0000000000 65535 f \n"
    for obj_id in range(1, 4):
        out += f"{offsets[obj_id]:010d} 00000 n \n"
    out += "trailer\n<< /Size 4 /Root 1 0 R >>\n"
    out += f"startxref\n{xref_pos}\n%%EOF\n"
    return out.encode("ascii")


# ------------------------------------------------------------- reading helpers


def _last_startxref(pdf: bytes) -> int:
    matches = re.findall(rb"startxref\s+(\d+)\s*%%EOF", pdf)
    assert matches, "no startxref"
    return int(matches[-1])


def _read_xref_stream(pdf: bytes, pos: int) -> tuple[dict, dict[int, tuple[int, int, int]]]:
    """Parse the (unfiltered) cross-reference stream object at ``pos``.

    Returns (dict fields, {object number: (type, field2, field3)})."""
    head = re.match(rb"(\d+) 0 obj\s*<<(.*?)>>\s*stream\r?\n", pdf[pos:], re.S)
    assert head is not None, f"no xref stream object at {pos}"
    d = head.group(2).decode("latin-1")
    assert re.search(r"/Type\s*/XRef\b", d), "object at startxref is not /Type /XRef"
    assert "/Filter" not in d, "test reader only handles unfiltered streams"
    w = [int(x) for x in re.search(r"/W\s*\[([^\]]*)\]", d).group(1).split()]
    size = int(re.search(r"/Size\s+(\d+)", d).group(1))
    im = re.search(r"/Index\s*\[([^\]]*)\]", d)
    index = [int(x) for x in im.group(1).split()] if im else [0, size]
    length = int(re.search(r"/Length\s+(\d+)", d).group(1))
    data_start = pos + head.end()
    data = pdf[data_start:data_start + length]
    assert pdf[data_start + length:data_start + length + 10] == b"\nendstream"

    row = sum(w)
    assert len(data) == row * sum(index[1::2]), "/Length does not match /W x /Index"
    entries: dict[int, tuple[int, int, int]] = {}
    i = 0
    for first, count in zip(index[0::2], index[1::2]):
        for n in range(count):
            fields = []
            p = i * row
            for width in w:
                fields.append(int.from_bytes(data[p:p + width], "big") if width else 1)
                p += width
            entries[first + n] = (fields[0], fields[1], fields[2])
            i += 1
    prev = re.search(r"/Prev\s+(\d+)", d)
    fields_out = {
        "id": int(head.group(1)),
        "size": size,
        "root": re.search(r"/Root\s+(\d+)\s+0\s+R", d).group(1),
        "prev": int(prev.group(1)) if prev else None,
        "index": index,
    }
    return fields_out, entries


def _walk_xref_stream_chain(pdf: bytes) -> list[tuple[int, dict, dict]]:
    """Follow startxref → /Prev → ... through cross-reference streams only,
    requiring every in-use entry to land on ``N 0 obj`` for its own number."""
    chain = []
    pos: int | None = _last_startxref(pdf)
    while pos is not None:
        assert not pdf.startswith(b"xref", pos), f"classic xref table at {pos} in a stream chain"
        fields, entries = _read_xref_stream(pdf, pos)
        for obj_id, (typ, off, _gen) in entries.items():
            if typ == 1:
                assert re.match(rb"%d 0 obj\b" % obj_id, pdf[off:off + 20]), (
                    f"entry for object {obj_id} -> {off} does not land on its header")
        chain.append((pos, fields, entries))
        pos = fields["prev"]
    return chain


def _byte_range(pdf: bytes) -> list[int]:
    m = list(re.finditer(rb"/ByteRange\s*\[(\d+) (\d+) (\d+) (\d+)\s*\]", pdf))
    assert m, "no finalized /ByteRange"
    return [int(x) for x in m[-1].groups()]


# ------------------------------------------------------------------------ tests


def test_detects_xref_stream_base() -> None:
    assert _pdf._parse_structure(build_xref_stream_pdf()).uses_xref_stream is True
    assert _pdf._parse_structure(build_classic_pdf()).uses_xref_stream is False


def test_startxref_at_non_xref_object_stays_classic() -> None:
    """A startxref that points at an ordinary object (approximate offsets in
    hand-made PDFs) must keep the classic format — only an object that really
    is /Type /XRef switches the output to a stream."""
    pdf = build_classic_pdf()
    catalog_off = pdf.index(b"1 0 obj")
    bogus = re.sub(rb"startxref\n\d+\n", b"startxref\n%d\n" % catalog_off, pdf)
    assert _pdf._parse_structure(bogus).uses_xref_stream is False
    inc = _pdf.prepare(bogus, T1).bytes[len(bogus):]
    assert b"\nxref\n" in inc
    assert b"/Type /XRef" not in inc


def test_classic_base_still_emits_classic_table() -> None:
    pdf = build_classic_pdf()
    inc = _pdf.prepare(pdf, T1).bytes[len(pdf):]
    assert b"\nxref\n" in inc
    assert b"/Type /XRef" not in inc


def test_prepare_on_xref_stream_base_appends_xref_stream() -> None:
    pdf = build_xref_stream_pdf()
    base_sx = _last_startxref(pdf)
    prep = _pdf.prepare(pdf, T1, "Signer")
    out = prep.bytes
    inc = out[len(pdf):]

    assert b"/Type /XRef" in inc
    assert b"\nxref\n" not in inc and b"trailer" not in inc

    new_sx = _last_startxref(out)
    assert new_sx > len(pdf)
    fields, entries = _read_xref_stream(out, new_sx)

    # Base max object number is 4 (its own xref stream): signature 5, field 6,
    # new AcroForm 7, so the new cross-reference stream is object 8.
    assert fields["id"] == 8
    assert fields["size"] == 9
    assert fields["root"] == "1"
    assert fields["prev"] == base_sx
    # One subsection per object, ascending: catalog, page, sig, field,
    # AcroForm and the stream itself.
    assert fields["index"] == [1, 1, 3, 1, 5, 1, 6, 1, 7, 1, 8, 1]
    assert entries[8] == (1, new_sx, 0)
    for obj_id, (typ, off, gen) in entries.items():
        assert typ == 1 and gen == 0
        assert off >= len(pdf), "revision must only reference newly appended objects"
        assert out[off:].startswith(b"%d 0 obj\n" % obj_id)
    assert out.endswith(b"startxref\n%d\n%%%%EOF\n" % new_sx)

    # ByteRange: sandwiches '<' hex '>' exactly, covers the whole file
    # (cross-reference stream included), and matches the reported digest.
    r1, r1_len, r2, r2_len = _byte_range(out)
    assert r1 == 0 and r2 + r2_len == len(out)
    assert out[r1_len:r1_len + 1] == b"<" and out[r2 - 1:r2] == b">"
    assert prep.contents_hex_offset == r1_len + 1
    assert prep.document_hash == hashlib.sha256(out[:r1_len] + out[r2:]).digest()
    assert _pdf.recover(out).document_hash == prep.document_hash


def test_full_b_lta_chain_on_xref_stream_base_round_trips() -> None:
    pdf = build_xref_stream_pdf()
    cms = _pattern(900, 251)
    prep = _pdf.prepare(pdf, T1, "Signer")
    signed = _pdf.embed(prep, cms)
    with_dss = _pdf.append_dss(signed, [_pattern(300, 13)], [_pattern(200, 17)], cms)
    dt = _pdf.prepare_doc_timestamp(with_dss)
    final = _pdf.embed_doc_timestamp(dt, _pattern(400, 23))

    # No classic table anywhere: base + signature + DSS + DocTimeStamp are all
    # cross-reference streams, chained newest → oldest.
    assert b"\nxref\n" not in final
    chain = _walk_xref_stream_chain(final)
    assert [pos for pos, _, _ in chain] == [
        _last_startxref(dt.bytes),
        _last_startxref(with_dss),
        _last_startxref(signed),
        _last_startxref(pdf),
    ]
    assert len(chain) == 4

    # Object numbers never collide: each revision's xref stream takes a fresh
    # number above everything that came before it.
    ids = [fields["id"] for _, fields, _ in chain]
    assert ids == sorted(ids, reverse=True) and len(set(ids)) == 4
    for _, fields, _ in chain[:-1]:
        assert fields["size"] == fields["id"] + 1

    # Every object of the newest revision chain resolves; the latest catalog
    # carries both the AcroForm and the DSS reference.
    resolved: dict[int, int] = {}
    for _, _, entries in reversed(chain):
        for obj_id, (typ, off, _gen) in entries.items():
            if typ == 1:
                resolved[obj_id] = off
    cat = final[resolved[1]:final.index(b"endobj", resolved[1])]
    assert b"/AcroForm" in cat and b"/DSS" in cat

    # The DocTimeStamp ByteRange covers the whole file and matches its digest.
    r1, r1_len, r2, r2_len = _byte_range(final)
    assert r1 == 0 and r2 + r2_len == len(final)
    assert dt.document_hash == hashlib.sha256(final[:r1_len] + final[r2:]).digest()

    # Re-parse with the signer's own structure reader: still a stream-format
    # document, so a further revision would also be a stream.
    s = _pdf._parse_structure(final)
    assert s.uses_xref_stream is True
    assert s.catalog_id == 1
    assert s.max_object_id == ids[0]

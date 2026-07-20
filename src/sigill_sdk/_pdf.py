"""Client-side half of Sigill's delegated PAdES signing.

Appends an ETSI.CAdES.detached signature revision to an existing PDF using the
incremental update model, computing the ByteRange digest locally so only a hash
ever has to reach Sigill. The CMS itself is built server-side
(``POST /seal/sign-pades-hash``) and embedded here.

Ported 1:1 from the .NET SDK's ``Sigill.Sdk.Internal.PdfIncrementalSigner``
(itself a port of the platform's ``Sigill.Api.Signing.PdfIncrementalSigner``,
minus the signed-attributes digest computation, which is server-side where the
signer certificate lives). Works with traditional xref-table PDFs, modern
xref-stream PDFs (PDF 1.5+), and PDFs whose key structural objects are packed
into compressed object streams (ObjStm). Uses only the stdlib (re, zlib,
hashlib).

Structural failures raise ValueError; the client wraps them in PdfUnsupported
so callers know to fall back to the server-side POST /seal/sign path.

Two-pass:

    prep = _pdf.prepare(pdf_bytes, now)
    cms = ...  # POST hash -> Sigill -> CMS
    signed = _pdf.embed(prep, cms)
"""
from __future__ import annotations

import hashlib
import re
import zlib
from dataclasses import dataclass
from datetime import datetime, timezone

#: Reserved /Contents slot for the (RSA + TST + OCSP) CMS.
DEFAULT_CMS_RESERVED_BYTES = 16_384

#: TST tokens are ~2-4 KB; 8 KB is generous headroom.
TST_RESERVED_BYTES = 8_192

_BR_TPL = "[0000000000 0000000000 0000000000 0000000000]"


@dataclass(frozen=True)
class PreparedPdf:
    """Output of prepare(): the PDF with a placeholder signature revision."""

    bytes: bytes
    """The original PDF plus the appended (placeholder) signature revision."""

    contents_hex_offset: int
    """Byte offset of the /Contents hex blob (just past the '<')."""

    contents_hex_length: int
    """Length of the hex blob in characters (reserved bytes * 2)."""

    document_hash: bytes
    """SHA-256 over the declared ByteRange — the only thing sent to Sigill."""


@dataclass(frozen=True)
class PreparedDocTimestamp:
    """Output of prepare_doc_timestamp(): placeholder DocTimeStamp revision."""

    bytes: bytes
    """The signed PDF plus the appended (placeholder) DocTimeStamp revision."""

    contents_hex_offset: int
    """Byte offset of the /Contents hex blob (just past the '<')."""

    contents_hex_length: int
    """Length of the hex blob in characters (reserved bytes * 2)."""

    document_hash: bytes
    """SHA-256 over the declared ByteRange — sent to /tsa/stamp-hash."""


# --------------------------------------------------------------- pass 1: prepare


def prepare(
    pdf: bytes,
    signing_time: datetime,
    reason: str | None = None,
    location: str | None = None,
    cms_reserved_bytes: int = DEFAULT_CMS_RESERVED_BYTES,
) -> PreparedPdf:
    """Append a placeholder signature revision and compute the ByteRange digest.

    :param pdf: the original PDF bytes; never mutated, never transmitted.
    :param signing_time: written into the signature dictionary's /M field.
    :param reason: optional /Reason field of the signature dictionary.
    :param location: optional /Location field of the signature dictionary.
    :param cms_reserved_bytes: size of the reserved /Contents slot.
    :raises ValueError: when the PDF's structure cannot be parsed locally.
    """
    empty_hex = "0" * (cms_reserved_bytes * 2)

    # /SubFilter /ETSI.CAdES.detached — the PAdES-compliant subfilter. The
    # server-built CMS carries signing-certificate-v2, which is what Adobe's
    # PAdES validation rules expect with this subfilter.
    body = (
        "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached\n"
        f"/ByteRange {_BR_TPL}\n/Contents <{empty_hex}>\n/M ({_fmt_date(signing_time)})\n"
    )
    if reason is not None:
        body += f"/Reason ({_pdf_esc(reason)})\n"
    if location is not None:
        body += f"/Location ({_pdf_esc(location)})\n"
    body += ">>"

    full, hex_off, hex_len, doc_hash = _append_signature_revision(
        pdf, body, "Sigill-Seal-1", cms_reserved_bytes,
        "Cannot locate /Contents placeholder")
    return PreparedPdf(full, hex_off, hex_len, doc_hash)


# ----------------------------------------------------------------- pass 2: embed


def embed(prep: PreparedPdf, cms_der: bytes) -> bytes:
    """Write the server-built CMS into the reserved /Contents slot."""
    if len(cms_der) * 2 > prep.contents_hex_length:
        raise ValueError(
            f"CMS ({len(cms_der)}B) > reserved slot ({prep.contents_hex_length // 2}B)")
    final = bytearray(prep.bytes)
    hex_str = cms_der.hex().ljust(prep.contents_hex_length, "0")
    final[prep.contents_hex_offset:prep.contents_hex_offset + prep.contents_hex_length] = (
        hex_str.encode("ascii"))
    return bytes(final)


# --------------------------------------------------------- pass 3: DSS (PAdES-LTV)


def append_dss(
    signed_pdf: bytes,
    cert_ders: list[bytes],
    ocsp_ders: list[bytes],
    signature_cms_der: bytes | None = None,
) -> bytes:
    """Append a Document Security Store dictionary as a third incremental update.

    PAdES-LTV, ISO 32000-2 §12.8.4.3.3: carries the certificate chain and OCSP
    responses returned by ``/seal/sign-pades-hash``. When ``signature_cms_der``
    is provided a /VRI subdictionary is written keyed by SHA-1(CMS) per
    ETSI TS 102 778-4 §4.3.
    """
    if not cert_ders and not ocsp_ders:
        return signed_pdf

    s = _parse_structure(signed_pdf)
    next_id = s.max_object_id + 1

    # Binary chunks + offset map kept separate so DER stream data is never
    # passed through a string encoder.
    chunks: list[bytes] = []
    offmap: dict[int, int] = {}
    pos = len(signed_pdf)

    def emit(obj_id: int, chunk: bytes) -> None:
        nonlocal pos
        offmap[obj_id] = pos
        chunks.append(chunk)
        pos += len(chunk)

    def stream_obj(obj_id: int, data: bytes) -> bytes:
        header = f"{obj_id} 0 obj\n<< /Length {len(data)} >>\nstream\n".encode("ascii")
        return header + data + b"\nendstream\nendobj\n"

    cert_ids = list(range(next_id, next_id + len(cert_ders)))
    next_id += len(cert_ders)
    ocsp_ids = list(range(next_id, next_id + len(ocsp_ders)))
    next_id += len(ocsp_ders)

    for obj_id, der in zip(cert_ids, cert_ders):
        emit(obj_id, stream_obj(obj_id, der))
    for obj_id, der in zip(ocsp_ids, ocsp_ders):
        emit(obj_id, stream_obj(obj_id, der))

    dss_id = next_id
    next_id += 1
    cert_refs = " ".join(f"{i} 0 R" for i in cert_ids)
    ocsp_refs = " ".join(f"{i} 0 R" for i in ocsp_ids)

    dss = ["<< /Type /DSS"]
    if cert_ids:
        dss.append(f"\n/Certs [{cert_refs}]")
    if ocsp_ids:
        dss.append(f"\n/OCSPs [{ocsp_refs}]")

    # /VRI links cert + OCSP data to this specific signature; without it,
    # Adobe and other strict validators report "LTV validation failed".
    if signature_cms_der is not None:
        vri_key = hashlib.sha1(signature_cms_der).hexdigest().upper()
        dss.append(f"\n/VRI << /{vri_key} <<")
        if cert_ids:
            dss.append(f" /Cert [{cert_refs}]")
        if ocsp_ids:
            dss.append(f" /OCSP [{ocsp_refs}]")
        dss.append(" >> >>")

    dss.append("\n>>")
    dss_body = "".join(dss)
    emit(dss_id, f"{dss_id} 0 obj\n{dss_body}\nendobj\n".encode("latin-1"))

    cat_id = s.catalog_id
    new_cat = _add_dss_to_catalog(s.catalog_content, dss_id)
    emit(cat_id, f"{cat_id} 0 obj\n{new_cat}\nendobj\n".encode("latin-1"))

    xref = _xref_trailer(offmap, next_id, cat_id, s.startxref, pos).encode("latin-1")
    return signed_pdf + b"".join(chunks) + xref


def _add_dss_to_catalog(cat: str, dss_id: int) -> str:
    m = re.search(r"/DSS\s+\d+\s+\d+\s+R", cat)
    if m:
        return cat.replace(m.group(0), f"/DSS {dss_id} 0 R")
    dd = cat.rfind(">>")
    return cat[:dd] + f"\n/DSS {dss_id} 0 R\n>>"


# ------------------------------------------------- pass 4: DocTimeStamp (B-LTA)


def prepare_doc_timestamp(signed_pdf: bytes, now: datetime) -> PreparedDocTimestamp:
    """Append a DocTimeStamp signature field as a fourth incremental update.

    PAdES B-LTA. The returned ``document_hash`` is the SHA-256 ByteRange digest
    to send to ``/tsa/stamp-hash``; embed the returned TimeStampToken with
    embed_doc_timestamp().
    """
    empty_hex = "0" * (TST_RESERVED_BYTES * 2)

    # /SubFilter /ETSI.RFC3161 identifies this as a document timestamp; the
    # /Contents slot holds the raw TimeStampToken DER.
    body = (
        "<< /Type /DocTimeStamp /Filter /Adobe.PPKLite /SubFilter /ETSI.RFC3161\n"
        f"/ByteRange {_BR_TPL}\n/Contents <{empty_hex}>\n/M ({_fmt_date(now)})\n>>"
    )

    full, hex_off, hex_len, doc_hash = _append_signature_revision(
        signed_pdf, body, "Sigill-DocTS-1", TST_RESERVED_BYTES,
        "Cannot locate DocTimeStamp /Contents placeholder")
    return PreparedDocTimestamp(full, hex_off, hex_len, doc_hash)


def embed_doc_timestamp(prep: PreparedDocTimestamp, tst_der: bytes) -> bytes:
    """Write the raw TimeStampToken DER into the reserved DocTimeStamp slot."""
    if len(tst_der) > TST_RESERVED_BYTES:
        raise ValueError(
            f"TST ({len(tst_der)}B) > reserved slot ({TST_RESERVED_BYTES}B)")
    final = bytearray(prep.bytes)
    hex_str = tst_der.hex().ljust(prep.contents_hex_length, "0")
    final[prep.contents_hex_offset:prep.contents_hex_offset + prep.contents_hex_length] = (
        hex_str.encode("ascii"))
    return bytes(final)


# ------------------------------------------------------ signature revision writer


def _append_signature_revision(
    pdf: bytes,
    sig_dict_body: str,
    field_title: str,
    reserved_bytes: int,
    placeholder_error: str,
) -> tuple:
    """Append a signature (or DocTimeStamp) revision with a zeroed /Contents slot.

    Returns (full_bytes, contents_hex_offset, contents_hex_length, document_hash).
    Shared byte-for-byte by prepare() and prepare_doc_timestamp() — the two only
    differ in the signature dictionary body, field name, and reserved slot size.
    """
    s = _parse_structure(pdf)

    next_id = s.max_object_id + 1
    sig_id = next_id
    next_id += 1
    fld_id = next_id
    next_id += 1
    page_id = s.page1_id
    cat_id = s.catalog_id
    if s.acroform_id > 0:
        af_id = s.acroform_id
    else:
        af_id = next_id
        next_id += 1

    base_off = len(pdf)
    parts: list[str] = []
    offmap: dict[int, int] = {}
    inc_len = 0

    def append_obj(obj_id: int, body: str) -> None:
        nonlocal inc_len
        offmap[obj_id] = base_off + inc_len
        chunk = f"{obj_id} 0 obj\n{body}\nendobj\n"
        parts.append(chunk)
        inc_len += len(chunk)

    append_obj(sig_id, sig_dict_body)

    append_obj(fld_id,
        "<< /Type /Annot /Subtype /Widget /Rect [0 0 0 0]\n"
        f"/FT /Sig /T ({field_title}) /V {sig_id} 0 R /P {page_id} 0 R /F 132 >>")

    append_obj(page_id, _add_annot_to_page(s.page1_content, fld_id))

    append_obj(af_id,
        _add_field_to_acroform(s.acroform_content, fld_id)
        if s.acroform_content is not None
        else f"<< /Fields [{fld_id} 0 R] /SigFlags 3 >>")

    append_obj(cat_id, _add_acroform_to_catalog(s.catalog_content, af_id))

    xref_pos = base_off + inc_len
    xref = _xref_trailer(offmap, next_id, cat_id, s.startxref, xref_pos)

    # Latin-1 keeps a 1:1 byte↔char mapping so binary-ish PDF content survives
    # the string round-trip.
    full = bytearray(pdf)
    full += ("".join(parts) + xref).encode("latin-1")

    empty_hex = "0" * (reserved_bytes * 2)
    angle = full.find(f"<{empty_hex}>".encode("ascii"), len(pdf))
    if angle < 0:
        raise ValueError(placeholder_error)

    # PAdES/ISO 32000 convention: the /Contents hex blob AND its angle brackets
    # are excluded from hashing — the declared ByteRange must sandwich
    # '<' + hex + '>' exactly. See the platform signer for the full derivation;
    # this must stay byte-identical with it.
    hex_off = angle + 1
    hex_len = reserved_bytes * 2
    r1, r1_len = 0, angle
    r2 = hex_off + hex_len + 1
    r2_len = len(full) - r2

    br_val = f"[{r1} {r1_len} {r2} {r2_len}]".ljust(len(_BR_TPL))
    br_off = full.find(_BR_TPL.encode("ascii"), len(pdf))
    if br_off >= 0:
        full[br_off:br_off + len(br_val)] = br_val.encode("ascii")

    doc_hash = _hash_ranges(full, r1, r1_len, r2, r2_len)
    return bytes(full), hex_off, hex_len, doc_hash


def _xref_trailer(
    offmap: dict[int, int], size: int, root_id: int, prev: int, xref_pos: int,
) -> str:
    """Emit the xref table + trailer + startxref for an incremental update."""
    lines = ["xref\n"]
    for obj_id in sorted(offmap):
        lines.append(f"{obj_id} 1\n{offmap[obj_id]:010d} 00000 n \n")
    lines.append(f"trailer\n<< /Size {size} /Root {root_id} 0 R /Prev {prev} >>\n")
    lines.append(f"startxref\n{xref_pos}\n%%EOF\n")
    return "".join(lines)


# ------------------------------------------------------- PDF structure parser


@dataclass(frozen=True)
class _Struct:
    max_object_id: int
    catalog_id: int
    catalog_content: str
    page1_id: int
    page1_content: str
    acroform_id: int
    acroform_content: str | None
    startxref: int


def _parse_structure(pdf: bytes) -> _Struct:
    t = pdf.decode("latin-1")

    # Find startxref (last occurrence — handles incremental updates)
    sx_matches = list(re.finditer(r"startxref\s+(\d+)\s*%%EOF", t))
    if not sx_matches:
        raise ValueError("startxref not found in PDF")
    sx = int(sx_matches[-1].group(1))

    # Object discovery: top-level "N 0 obj" offsets plus objects unpacked from
    # /Type /ObjStm streams. Last write wins so incremental updates override
    # originals correctly.
    offsets = _scan_objects(t)
    compressed = _scan_compressed_objects(pdf, t, offsets)

    # Most recent /Root reference (trailer dicts are never compressed).
    root_matches = list(re.finditer(r"/Root\s+(\d+)\s+\d+\s+R", t))
    if not root_matches:
        raise ValueError("/Root not found in PDF")
    cat_id = int(root_matches[-1].group(1))
    cat = _get_obj(t, offsets, compressed, cat_id)

    pages_m = re.search(r"/Pages\s+(\d+)\s+\d+\s+R", cat)
    if pages_m is None:
        raise ValueError("/Pages not found in catalog")
    pages = _get_obj(t, offsets, compressed, int(pages_m.group(1)))

    p1_id = _walk_to_first_leaf_page(t, offsets, compressed, pages)
    p1 = _get_obj(t, offsets, compressed, p1_id)

    af_id = 0
    af_content: str | None = None
    am = re.search(r"/AcroForm\s+(\d+)\s+\d+\s+R", cat)
    if am is not None:
        af_id = int(am.group(1))
        af_content = _get_obj(t, offsets, compressed, af_id)

    max_id = max(max(offsets, default=0), max(compressed, default=0))

    return _Struct(max_id, cat_id, cat, p1_id, p1, af_id, af_content, sx)


def _walk_to_first_leaf_page(
    t: str,
    offsets: dict[int, int],
    compressed: dict[int, str],
    node: str,
) -> int:
    # Loop guarded — if a malicious or corrupt PDF cycles, bail.
    for _hop in range(64):
        kids_m = re.search(r"/Kids\s*\[\s*(\d+)", node)
        if kids_m is None:
            raise ValueError("/Kids not found in Pages node")
        kid_id = int(kids_m.group(1))
        kid = _get_obj(t, offsets, compressed, kid_id)
        if re.search(r"/Type\s*/Page\b(?!s)", kid):
            return kid_id
        node = kid
    raise ValueError("Page tree deeper than 64 levels — refusing to descend")


def _scan_objects(t: str) -> dict[int, int]:
    d: dict[int, int] = {}
    for m in re.finditer(r"(?<![.\d])(\d+)\s+0\s+obj[\s<\[]", t):
        obj_id = int(m.group(1))
        if obj_id > 0:
            d[obj_id] = m.start()  # overwrite — later definition takes precedence
    return d


def _scan_compressed_objects(
    pdf: bytes, t: str, top_level_offsets: dict[int, int],
) -> dict[int, str]:
    result: dict[int, str] = {}

    for obj_stm_id, header_off in top_level_offsets.items():
        hm = re.compile(rf"\b{obj_stm_id}\s+0\s+obj\b").search(t, header_off)
        if hm is None:
            continue
        dict_start = hm.end()

        stream_kw = t.find("stream", dict_start)
        if stream_kw < 0:
            continue
        dict_text = t[dict_start:stream_kw]

        if not re.search(r"/Type\s*/ObjStm", dict_text):
            continue

        n = _parse_int_field(dict_text, "N")
        first = _parse_int_field(dict_text, "First")
        length = _parse_int_field(dict_text, "Length")

        # Filter must be FlateDecode (allow array form like [/FlateDecode]).
        # /Predictor on ObjStm is legal per spec but unseen in the wild —
        # fail loudly so the caller can fall back to server-side sealing.
        if not re.search(r"/Filter\s*(\[\s*)?/FlateDecode", dict_text):
            raise ValueError(
                f"Object stream {obj_stm_id} uses unsupported filter — "
                "only FlateDecode is supported")
        if re.search(r"/Predictor\s+[2-9]", dict_text):
            raise ValueError(
                f"Object stream {obj_stm_id} uses /Predictor — not supported")

        data_start = stream_kw + len("stream")
        if data_start < len(pdf) and pdf[data_start:data_start + 1] == b"\r":
            data_start += 1
        if data_start < len(pdf) and pdf[data_start:data_start + 1] == b"\n":
            data_start += 1

        if data_start + length > len(pdf):
            raise ValueError(
                f"Object stream {obj_stm_id} declares /Length {length} "
                "but file is too short")

        decoded = _flate_decode(pdf, data_start, length)
        decoded_text = decoded.decode("latin-1")

        header_slice = decoded_text[:min(first, len(decoded_text))]
        ints = re.findall(r"\d+", header_slice)
        if len(ints) < n * 2:
            raise ValueError(
                f"Object stream {obj_stm_id} header has {len(ints)} ints, "
                f"expected at least {n * 2}")

        for i in range(n):
            obj_id = int(ints[i * 2])
            rel_off = int(ints[i * 2 + 1])
            body_start = first + rel_off
            if i + 1 < n:
                body_end = first + int(ints[(i + 1) * 2 + 1])
            else:
                body_end = len(decoded_text)
            if body_start < 0 or body_end > len(decoded_text) or body_start > body_end:
                continue  # malformed entry, skip
            result[obj_id] = decoded_text[body_start:body_end].strip()

    return result


def _parse_int_field(dict_text: str, name: str) -> int:
    m = re.search(rf"/{name}\s+(\d+)", dict_text)
    if m is None:
        raise ValueError(f"ObjStm dict missing /{name}")
    return int(m.group(1))


def _flate_decode(src: bytes, offset: int, length: int) -> bytes:
    """FlateDecode = zlib-wrapped deflate; zlib.decompress handles the header."""
    try:
        return zlib.decompress(src[offset:offset + length])
    except zlib.error as e:
        raise ValueError(f"FlateDecode failed: {e}") from e


def _get_obj(
    t: str,
    offsets: dict[int, int],
    compressed: dict[int, str],
    obj_id: int,
) -> str:
    if obj_id in offsets:
        om = re.compile(rf"\b{obj_id}\s+0\s+obj\b").search(t, offsets[obj_id])
        if om is None:
            raise ValueError(
                f"Object {obj_id} header not found from offset {offsets[obj_id]}")
        s = om.end()
        while s < len(t) and t[s] in " \n\r":
            s += 1
        e = t.find("endobj", s)
        if e < 0:
            raise ValueError(f"endobj missing for object {obj_id}")
        return t[s:e].strip()
    if obj_id in compressed:
        return compressed[obj_id]
    raise ValueError(
        f"Object {obj_id} not found in PDF (not top-level, not in any object stream)")


# ----------------------------------------------------------- PDF object patchers


def _add_annot_to_page(page: str, fld_id: int) -> str:
    m = re.search(r"/Annots\s*\[\s*", page)
    if m:
        c = page.index("]", m.end())
        return page[:c] + f" {fld_id} 0 R" + page[c:]
    dd = page.rfind(">>")
    return page[:dd] + f"\n/Annots [{fld_id} 0 R]\n>>"


def _add_field_to_acroform(af: str, fld_id: int) -> str:
    m = re.search(r"/Fields\s*\[\s*", af)
    if m:
        c = af.index("]", m.end())
        r = af[:c] + f" {fld_id} 0 R" + af[c:]
    else:
        dd = af.rfind(">>")
        r = af[:dd] + f"\n/Fields [{fld_id} 0 R]\n>>"
    if "/SigFlags" not in r:
        dd = r.rfind(">>")
        r = r[:dd] + "\n/SigFlags 3\n>>"
    return r


def _add_acroform_to_catalog(cat: str, af_id: int) -> str:
    m = re.search(r"/AcroForm\s+\d+\s+\d+\s+R", cat)
    if m:
        return cat.replace(m.group(0), f"/AcroForm {af_id} 0 R")
    dd = cat.rfind(">>")
    return cat[:dd] + f"\n/AcroForm {af_id} 0 R\n>>"


# ---------------------------------------------------------------------- helpers


def _hash_ranges(full: bytearray, r1: int, r1_len: int, r2: int, r2_len: int) -> bytes:
    h = hashlib.sha256()
    mv = memoryview(full)
    h.update(mv[r1:r1 + r1_len])
    h.update(mv[r2:r2 + r2_len])
    return h.digest()


def _fmt_date(dt: datetime) -> str:
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc)
    return f"D:{dt:%Y%m%d%H%M%S}+00'00'"


def _pdf_esc(s: str) -> str:
    return s.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")

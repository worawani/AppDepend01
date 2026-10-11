"""Shared import framework: fatal file errors vs. record-level issues, bounded issue
logs, rejected-row capture and safe text decoding. Used by every importer."""

from __future__ import annotations

import codecs
import csv
import io
from collections import Counter
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import BinaryIO


class FileError(ValueError):
    """Fatal: the file as a whole is rejected (unsupported format, invalid schema,
    missing required fields, unsafe to parse). Nothing from it is imported."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


@dataclass
class Issue:
    severity: str            # error | warning | info
    code: str
    message: str
    row_number: int | None = None
    field: str | None = None
    raw_value: str | None = None


@dataclass
class RejectedRow:
    row_number: int
    raw: str                 # the original line, re-serialised from the parsed fields
    errors: list[dict]       # [{"code", "field", "message", "raw_value"}]


class IssueLog:
    """Keeps every count, but only the first `examples_per_code` issues of each code.
    A 5-million-row file with one bad column must not produce 5 million issue rows,
    and the truncation is reported, never hidden."""

    def __init__(self, examples_per_code: int = 100):
        self.examples_per_code = examples_per_code
        self.counts: Counter[tuple[str, str]] = Counter()
        self.kept: list[Issue] = []

    def add(self, issue: Issue) -> None:
        key = (issue.severity, issue.code)
        self.counts[key] += 1
        if self.counts[key] <= self.examples_per_code:
            self.kept.append(issue)

    def count(self, severity: str) -> int:
        return sum(n for (sev, _), n in self.counts.items() if sev == severity)

    def summary(self) -> list[dict]:
        return [{"severity": s, "code": c, "count": n, "shown": min(n, self.examples_per_code)}
                for (s, c), n in sorted(self.counts.items())]

    def issues(self) -> list[Issue]:
        out = list(self.kept)
        for (sev, code), n in sorted(self.counts.items()):
            if n > self.examples_per_code:
                out.append(Issue("info", "issues_truncated",
                                 f"{n - self.examples_per_code:,} more '{code}' {sev}(s) not listed individually "
                                 f"({n:,} in total)."))
        out.sort(key=lambda i: (i.row_number is not None, i.row_number or 0))
        return out


def sniff_dialect(sample: str):
    try:
        return csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        return csv.excel


def decode_bytes(data: bytes, encoding: str | None) -> tuple[str, str]:
    if encoding:
        try:
            return data.decode(encoding), encoding
        except (LookupError, UnicodeDecodeError) as exc:
            raise FileError("encoding", f"File cannot be decoded as {encoding}: {exc}") from exc
    try:
        return data.decode("utf-8-sig"), "utf-8"
    except UnicodeDecodeError as exc:
        raise FileError(
            "encoding",
            f"File is not valid UTF-8 (byte offset {exc.start}). Save it as 'CSV UTF-8' or pass the encoding explicitly "
            "(for example cp874 for Thai Windows exports).") from exc


def text_lines(stream: BinaryIO, encoding: str | None) -> tuple[Iterator[str], str]:
    """Stream-decode a binary file line by line (large telemetry files are not loaded whole).
    Each line is decoded strictly, so a bad byte is a fatal FileError naming the exact line.
    Byte-wise line splitting is only valid for ASCII-compatible encodings, so UTF-16/32 are refused."""
    enc = encoding or "utf-8-sig"
    try:
        info = codecs.lookup(enc)
    except LookupError as exc:
        raise FileError("encoding", f"Unknown encoding '{encoding}'.") from exc
    if info.name.startswith(("utf-16", "utf-32")):
        raise FileError("encoding", "UTF-16/UTF-32 files are not supported; save the file as UTF-8 CSV.")
    reader = stream if hasattr(stream, "readline") else io.BufferedReader(stream)
    decode_as = "utf-8" if info.name == "utf-8-sig" else info.name

    def gen() -> Iterator[str]:
        for line_no, raw in enumerate(iter(reader.readline, b""), 1):
            if line_no == 1:
                if raw.startswith((codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE)):
                    raise FileError("encoding", "File is UTF-16 (e.g. Excel 'Unicode Text'); save it as UTF-8 CSV.")
                if raw.startswith(codecs.BOM_UTF8):
                    raw = raw[3:]
            if b"\x00" in raw:
                raise FileError("binary", f"NUL byte on line {line_no}: not a text CSV.")
            try:
                yield raw.decode(decode_as, errors="strict")
            except UnicodeDecodeError as exc:
                raise FileError("encoding", f"Invalid {decode_as} byte sequence on line {line_no} (byte {exc.start + 1}). "
                                "Save the file as UTF-8 or pass the correct encoding.") from exc

    return gen(), ("utf-8" if info.name == "utf-8-sig" else info.name)


def reserialise(fields: list[str], delimiter: str = ",") -> str:
    buf = io.StringIO()
    csv.writer(buf, delimiter=delimiter, lineterminator="").writerow(fields)
    return buf.getvalue()


def check_invalid_ratio(total: int, rejected: int, max_ratio: float, min_rows: int = 20) -> None:
    """A file where most rows fail is far more likely the wrong format than a few bad
    rows, so it is rejected as a whole rather than offered for partial import."""
    if total >= min_rows and rejected / total > max_ratio:
        raise FileError("too_many_invalid_records",
                        f"{rejected:,} of {total:,} records are invalid ({rejected / total:.0%} > {max_ratio:.0%}). "
                        "The file is probably in a different format than selected; it was not parsed further.")


@dataclass
class ValidationSummary:
    """What the preview and the error report show, for any importer."""
    parser: str
    parser_version: str
    schema_version: str
    encoding: str
    rows: int
    accepted: int
    rejected: int
    errors: int
    warnings: int
    issue_counts: list[dict] = field(default_factory=list)

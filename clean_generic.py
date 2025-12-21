#!/usr/bin/env python3
"""
format_text.py

Generic formatter for "single-line" log messages that contain escaped newlines
(e.g., '\\n', '\\t') and possibly fenced code blocks.

What it does:
- Converts escaped sequences like \\n \\t into real newlines/tabs.
- Normalizes newlines.
- Optionally wraps *non-code* paragraphs to a readable width.
- Preserves fenced code blocks (``` ... ```) exactly (no wrapping inside).

Usage:
  python format_text.py --in input.txt --out formatted.txt
  python format_text.py --in input.txt
  cat input.txt | python format_text.py
"""

from __future__ import annotations

import argparse
import sys
import textwrap
from typing import List, Tuple


def decode_escapes(s: str) -> str:
    """
    Convert common escape sequences (\\n, \\t, \\r, \\") into real characters.
    Uses unicode_escape decoding, which is handy for logs that literally contain '\\n'.
    """
    return (
        s.replace("\\r\\n", "\n")
         .replace("\\n", "\n")
         .replace("\\t", "\t")
         .replace("\\r", "\n")
    )


def split_fenced_code_blocks(text: str) -> List[Tuple[str, str]]:
    """
    Splits text into a list of (kind, chunk) where kind is 'text' or 'code'.
    Fenced code blocks are delimited by lines starting with ```.

    This is intentionally simple and treats anything between matching fences as code.
    """
    lines = text.splitlines(keepends=True)
    parts: List[Tuple[str, str]] = []
    buf: List[str] = []
    in_code = False

    def flush(kind: str):
        nonlocal buf
        if buf:
            parts.append((kind, "".join(buf)))
            buf = []

    for line in lines:
        if line.lstrip().startswith("```"):
            if in_code:
                # Closing fence goes with the code block
                buf.append(line)
                flush("code")
                in_code = False
            else:
                # Starting fence begins a new code block
                flush("text")
                in_code = True
                buf.append(line)
        else:
            buf.append(line)

    # Flush leftovers (unclosed code fence => treat remainder as code)
    flush("code" if in_code else "text")
    return parts


def wrap_paragraphs(text: str, width: int) -> str:
    """
    Wrap paragraphs in 'text' segments, leaving blank lines intact.
    """
    out_lines: List[str] = []
    paragraph: List[str] = []

    def flush_paragraph():
        nonlocal paragraph
        if not paragraph:
            return
        joined = " ".join(line.strip() for line in paragraph if line.strip() != "")
        if joined.strip():
            out_lines.append(textwrap.fill(joined, width=width))
        else:
            out_lines.append("")
        paragraph = []

    for line in text.splitlines():
        if line.strip() == "":
            flush_paragraph()
            out_lines.append("")  # preserve blank line
        else:
            paragraph.append(line)

    flush_paragraph()
    return "\n".join(out_lines) + ("\n" if text.endswith("\n") else "")


def normalize_newlines(s: str) -> str:
    return s.replace("\r\n", "\n").replace("\r", "\n")


def format_message(raw: str, width: int | None = 88, wrap: bool = True) -> str:
    """
    Generic formatter: decode escapes, normalize newlines, wrap non-code text.
    """
    decoded = normalize_newlines(decode_escapes(raw))

    parts = split_fenced_code_blocks(decoded)
    formatted_chunks: List[str] = []

    for kind, chunk in parts:
        if kind == "code" or not wrap or width is None:
            formatted_chunks.append(chunk)
        else:
            formatted_chunks.append(wrap_paragraphs(chunk, width=width))

    result = "".join(formatted_chunks)

    # Ensure trailing newline if output is to terminal (nice UX); keep exact if file.
    return result


def read_input(path: str | None) -> str:
    if path:
        return open(path, "r", encoding="utf-8").read()
    return sys.stdin.read()


def write_output(path: str | None, content: str) -> None:
    if path:
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(content)
    else:
        sys.stdout.write(content)


def main() -> int:
    parser = argparse.ArgumentParser(description="Format escaped log-like text into readable output.")
    parser.add_argument("--in", dest="in_path", help="Input file path (default: stdin)")
    parser.add_argument("--out", dest="out_path", help="Output file path (default: stdout)")
    parser.add_argument("--width", type=int, default=88, help="Wrap width for non-code text (default: 88)")
    parser.add_argument("--no-wrap", action="store_true", help="Disable paragraph wrapping (preserve line lengths)")
    args = parser.parse_args()

    raw = read_input(args.in_path)
    formatted = format_message(raw, width=args.width, wrap=not args.no_wrap)
    write_output(args.out_path, formatted)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

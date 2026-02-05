#!/usr/bin/env python3
from __future__ import annotations

import argparse
import csv
from pathlib import Path


def _iter_csv_files(path: Path) -> list[Path]:
    if not path.exists():
        return []
    if path.is_file():
        return [path]
    return list(path.rglob('*.csv'))


def _normalize(value: str) -> str | None:
    value = value.strip().lower()
    if not value:
        return None
    if value.startswith('*.'):
        value = value[2:]
    return value.lstrip('.')


def extract_oneforall(source: Path, output: Path) -> None:
    results: set[str] = set()
    for csv_path in _iter_csv_files(source):
        try:
            with csv_path.open('r', encoding='utf-8', errors='ignore', newline='') as fh:
                reader = csv.DictReader(fh)
                for row in reader:
                    value = row.get('subdomain') if isinstance(row, dict) else None
                    if not value:
                        continue
                    # Some rows contain multiple values separated by comma
                    for item in str(value).split(','):
                        normalized = _normalize(item)
                        if normalized:
                            results.add(normalized)
        except OSError:
            continue

    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text('\n'.join(sorted(results)) + ('\n' if results else ''), encoding='utf-8')


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description='Extract subdomains from OneForAll CSV output.')
    parser.add_argument('--input', required=True, help='OneForAll CSV file or directory')
    parser.add_argument('--output', required=True, help='Output file')
    return parser


def main() -> int:
    args = build_parser().parse_args()
    extract_oneforall(Path(args.input), Path(args.output))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())

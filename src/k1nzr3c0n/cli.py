from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .workflow import WorkflowError, parse_var_overrides, run_workflow


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='k1nzr3c0n',
        description='Workflow runner for security scanning',
    )
    sub = parser.add_subparsers(dest='command', required=True)

    run = sub.add_parser('run', help='Run a workflow')
    run.add_argument('-w', '--workflow', required=True, help='Path to workflow YAML')
    run.add_argument('-t', '--target', required=True, help='Target identifier')
    run.add_argument('-o', '--out', default=None, help='Output workspace directory')
    run.add_argument('--print-plan', action='store_true', help='Print resolved commands and exit')
    run.add_argument('--continue-on-error', action='store_true', help='Continue even if a step fails')
    run.add_argument('--vars', nargs='*', default=[], help='Override workflow vars: key=value')
    run.add_argument('--resume', action='store_true', help='Resume from existing workspace (--out)')

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)

    if args.command == 'run':
        try:
            var_overrides = parse_var_overrides(args.vars)
            run_workflow(
                workflow_path=Path(args.workflow),
                target=args.target,
                out_dir=Path(args.out) if args.out else None,
                print_plan=args.print_plan,
                continue_on_error=args.continue_on_error,
                var_overrides=var_overrides,
                resume=args.resume,
            )
        except WorkflowError as exc:
            print(f'[x] {exc}', file=sys.stderr)
            return 2

    return 0

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .workflow import (
    WorkflowError,
    _execution_levels,
    load_workflow,
    parse_var_overrides,
    render_template,
    run_workflow,
    topological_order,
)

_WORKFLOWS_DEFAULT = Path('workflows')


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog='k1nzr3c0n',
        description='Security reconnaissance workflow runner',
    )
    sub = parser.add_subparsers(dest='command', required=True)

    # ── run ───────────────────────────────────────────────────────────────────
    run_p = sub.add_parser('run', help='Execute a workflow against a target')
    run_p.add_argument('-w', '--workflow', required=True, metavar='YAML', help='Workflow file path')
    run_p.add_argument('-t', '--target', required=True, help='Scan target (domain, IP, CIDR)')
    run_p.add_argument('-o', '--out', default=None, metavar='DIR', help='Output workspace directory')
    run_p.add_argument('--plan', action='store_true', help='Print resolved commands without executing')
    run_p.add_argument('--continue-on-error', action='store_true', help='Keep running when a step fails')
    run_p.add_argument('--vars', nargs='*', default=[], metavar='KEY=VALUE',
                       help='Override workflow variables (repeatable)')
    run_p.add_argument('--resume', action='store_true',
                       help='Resume a previous run (requires --out pointing at existing workspace)')

    # ── validate ─────────────────────────────────────────────────────────────
    val_p = sub.add_parser('validate', help='Validate a workflow file without running it')
    val_p.add_argument('workflow', metavar='YAML', help='Workflow file to validate')

    # ── plan ─────────────────────────────────────────────────────────────────
    plan_p = sub.add_parser('plan', help='Show the execution plan for a workflow')
    plan_p.add_argument('-w', '--workflow', required=True, metavar='YAML', help='Workflow file path')
    plan_p.add_argument('-t', '--target', required=True, help='Target (used for variable rendering)')
    plan_p.add_argument('--vars', nargs='*', default=[], metavar='KEY=VALUE',
                        help='Override workflow variables')

    # ── list ─────────────────────────────────────────────────────────────────
    list_p = sub.add_parser('list', help='List available workflows')
    list_p.add_argument('-d', '--dir', default=str(_WORKFLOWS_DEFAULT), metavar='DIR',
                        help=f'Workflows directory (default: {_WORKFLOWS_DEFAULT})')

    return parser


def _cmd_validate(args: argparse.Namespace) -> int:
    path = Path(args.workflow)
    try:
        data = load_workflow(path)
    except WorkflowError as exc:
        print(f'[x] {exc}', file=sys.stderr)
        return 2
    except Exception as exc:
        print(f'[x] Unexpected error: {exc}', file=sys.stderr)
        return 2

    steps = data['steps']
    n = len(steps)
    print(f'[+] {path.name} — OK ({n} step{"s" if n != 1 else ""})')

    defined_vars = sorted(data.get('vars') or {})
    if defined_vars:
        print(f'    Vars: {", ".join(defined_vars)}')

    try:
        ordered = topological_order(steps)
        levels = _execution_levels(ordered)
        print(f'    Levels: {len(levels)} (max parallelism: {max((len(l) for l in levels), default=1)})')
    except WorkflowError as exc:
        print(f'[x] Topology error: {exc}', file=sys.stderr)
        return 2

    return 0


def _cmd_plan(args: argparse.Namespace) -> int:
    path = Path(args.workflow)
    try:
        var_overrides = parse_var_overrides(args.vars)
        data = load_workflow(path)
    except WorkflowError as exc:
        print(f'[x] {exc}', file=sys.stderr)
        return 2

    merged = {**(data.get('vars') or {}), **var_overrides}
    ctx: dict = {
        **merged,
        'vars': merged,
        'target': args.target,
        'workspace': '<workspace>',
        'timestamp': '<timestamp>',
        'steps': {},
    }

    try:
        ordered = topological_order(data['steps'])
        levels = _execution_levels(ordered)
    except WorkflowError as exc:
        print(f'[x] {exc}', file=sys.stderr)
        return 2

    for level_idx, level_steps in enumerate(levels, start=1):
        print(f'\n  Level {level_idx}  ({"sequential" if len(level_steps) == 1 else f"{len(level_steps)} parallel"})')
        for step in level_steps:
            step_id = step['id']
            fanout = step.get('fanout')
            when = step.get('when')
            tags: list[str] = []
            if step.get('optional'):
                tags.append('optional')
            if step.get('skip_if_exists'):
                tags.append('skip-if-exists')
            if step.get('shell'):
                tags.append('shell')
            tag_str = f'  [{", ".join(tags)}]' if tags else ''

            if fanout:
                print(f'    {step_id}: (fanout × {len(fanout)}){tag_str}')
                for child in fanout:
                    try:
                        cmd = render_template(child['run'], ctx, allow_missing=True)
                    except WorkflowError:
                        cmd = child['run']
                    print(f'      .{child["id"]}: {cmd}')
            else:
                try:
                    cmd = render_template(step.get('run', ''), ctx, allow_missing=True)
                except WorkflowError:
                    cmd = step.get('run', '')
                when_note = f'  (when: {when})' if when else ''
                print(f'    {step_id}{tag_str}{when_note}: {cmd}')
    print()
    return 0


def _cmd_list(args: argparse.Namespace) -> int:
    wf_dir = Path(args.dir)
    if not wf_dir.is_dir():
        print(f'[x] Directory not found: {wf_dir}', file=sys.stderr)
        return 2

    yaml_files = sorted(wf_dir.glob('**/*.yaml')) + sorted(wf_dir.glob('**/*.yml'))
    if not yaml_files:
        print(f'No .yaml files found in {wf_dir}')
        return 0

    for wf_path in yaml_files:
        try:
            data = load_workflow(wf_path)
        except WorkflowError as exc:
            print(f'  [!] {wf_path.name}: {exc}')
            continue

        steps = data['steps']
        vars_defined = sorted(data.get('vars') or {})
        var_str = f'  vars: {", ".join(vars_defined)}' if vars_defined else ''
        print(f'  {wf_path.relative_to(wf_dir)}  ({len(steps)} steps){var_str}')

    return 0


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
                print_plan=args.plan,
                continue_on_error=args.continue_on_error,
                var_overrides=var_overrides,
                resume=args.resume,
            )
        except WorkflowError as exc:
            print(f'[x] {exc}', file=sys.stderr)
            return 2
        except KeyboardInterrupt:
            print('\n[!] Interrupted.', file=sys.stderr)
            return 130

    elif args.command == 'validate':
        return _cmd_validate(args)

    elif args.command == 'plan':
        return _cmd_plan(args)

    elif args.command == 'list':
        return _cmd_list(args)

    return 0

from __future__ import annotations

from pathlib import Path
import json
import os
import re
import shlex
import shutil
import subprocess
import time
from typing import Any

import yaml


class WorkflowError(RuntimeError):
    pass


_PLACEHOLDER = re.compile(r'\{([A-Za-z0-9_.-]+)\}')


def info(message: str) -> None:
    print(f'[+] {message}')


def warn(message: str) -> None:
    print(f'[!] {message}')


def parse_var_overrides(items: list[str]) -> dict[str, str]:
    overrides: dict[str, str] = {}
    for item in items:
        if '=' not in item:
            raise WorkflowError(f'Invalid --vars entry: {item!r}. Use key=value.')
        key, value = item.split('=', 1)
        key = key.strip()
        if not key:
            raise WorkflowError('Invalid --vars entry: empty key.')
        overrides[key] = value
    return overrides


def load_workflow(path: Path) -> dict[str, Any]:
    if not path.exists():
        raise WorkflowError(f'Workflow not found: {path}')

    raw = path.read_text(encoding='utf-8')
    data = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        raise WorkflowError('Workflow must be a YAML mapping at top level.')

    steps = data.get('steps')
    if not isinstance(steps, list) or not steps:
        raise WorkflowError("Workflow must contain a non-empty 'steps' list.")

    seen: set[str] = set()
    for idx, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            raise WorkflowError(f'Step #{idx} must be a mapping.')

        step_id = step.get('id')
        if not step_id or not isinstance(step_id, str):
            raise WorkflowError(f'Step #{idx} missing valid id.')
        if step_id in seen:
            raise WorkflowError(f'Duplicate step id: {step_id}')
        seen.add(step_id)

        run_cmd = step.get('run')
        if not run_cmd or not isinstance(run_cmd, str):
            raise WorkflowError(f"Step '{step_id}' missing valid run.")

        depends = step.get('depends_on', [])
        if depends is None:
            depends = []
        if isinstance(depends, str):
            depends = [depends]
        if not isinstance(depends, list) or any(not isinstance(x, str) for x in depends):
            raise WorkflowError(f"Step '{step_id}' has invalid depends_on.")
        step['depends_on'] = depends

        retries = step.get('retries', 0)
        if retries is None:
            retries = 0
        try:
            step['retries'] = int(retries)
        except (TypeError, ValueError) as exc:
            raise WorkflowError(f"Step '{step_id}' has invalid retries.") from exc

        skip_if_exists = step.get('skip_if_exists', False)
        if not isinstance(skip_if_exists, bool):
            raise WorkflowError(f"Step '{step_id}' has invalid skip_if_exists.")
        step['skip_if_exists'] = skip_if_exists

        run_on_failed_deps = step.get('run_on_failed_deps', False)
        if not isinstance(run_on_failed_deps, bool):
            raise WorkflowError(f"Step '{step_id}' has invalid run_on_failed_deps.")
        step['run_on_failed_deps'] = run_on_failed_deps

        requires = step.get('requires', [])
        if requires is None:
            requires = []
        if isinstance(requires, (str, dict)):
            requires = [requires]
        if not isinstance(requires, list):
            raise WorkflowError(f"Step '{step_id}' has invalid requires.")
        normalized: list[dict[str, Any]] = []
        for item in requires:
            if isinstance(item, str):
                normalized.append({'path': item, 'min_bytes': 0})
                continue
            if isinstance(item, dict):
                path_value = item.get('path')
                if not path_value or not isinstance(path_value, str):
                    raise WorkflowError(
                        f"Step '{step_id}' requires entries must include string path."
                    )
                min_bytes = item.get('min_bytes', 0)
                if min_bytes is None:
                    min_bytes = 0
                try:
                    min_bytes = int(min_bytes)
                except (TypeError, ValueError) as exc:
                    raise WorkflowError(
                        f"Step '{step_id}' has invalid requires.min_bytes."
                    ) from exc
                normalized.append({'path': path_value, 'min_bytes': min_bytes})
                continue
            raise WorkflowError(f"Step '{step_id}' has invalid requires entry.")
        step['requires'] = normalized

    data['steps'] = steps

    return data


def _resolve_key(key: str, ctx: dict[str, Any]) -> Any:
    current: Any = ctx
    for part in key.split('.'):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def render_template(template: str, ctx: dict[str, Any]) -> str:
    if not isinstance(template, str):
        return template

    def repl(match: re.Match[str]) -> str:
        key = match.group(1)
        value = _resolve_key(key, ctx)
        if value is None:
            raise WorkflowError(f'Unknown template key: {key}')
        return str(value)

    return _PLACEHOLDER.sub(repl, template)


def topological_order(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {step['id']: step for step in steps}
    index = {step['id']: i for i, step in enumerate(steps)}
    deps = {sid: set(by_id[sid].get('depends_on', [])) for sid in by_id}

    for sid, ds in deps.items():
        missing = [d for d in ds if d not in by_id]
        if missing:
            raise WorkflowError(
                f"Step '{sid}' depends on missing step(s): {', '.join(missing)}"
            )

    ready = [sid for sid, ds in deps.items() if not ds]
    ready.sort(key=lambda s: index[s])

    order: list[str] = []
    while ready:
        sid = ready.pop(0)
        order.append(sid)
        for other, ds in deps.items():
            if sid in ds:
                ds.remove(sid)
                if not ds and other not in order and other not in ready:
                    ready.append(other)
                    ready.sort(key=lambda s: index[s])

    if len(order) != len(by_id):
        raise WorkflowError('Dependency cycle detected in steps.')

    return [by_id[sid] for sid in order]


def _warn_missing_tool(command: str) -> None:
    try:
        parts = shlex.split(command, posix=os.name != 'nt')
    except ValueError:
        return
    if not parts:
        return
    tool = parts[0]
    if shutil.which(tool) is None:
        warn(f'Tool not found in PATH: {tool}')


def _check_requires(requires: list[dict[str, Any]], ctx: dict[str, Any]) -> bool:
    if not requires:
        return True

    workspace = Path(str(ctx.get('workspace', '.')))
    for req in requires:
        path_value = render_template(str(req['path']), ctx)
        req_path = Path(path_value)
        if not req_path.is_absolute():
            req_path = workspace / req_path

        if not req_path.exists():
            warn(f'Required path missing: {req_path}')
            return False

        min_bytes = int(req.get('min_bytes', 0))
        if min_bytes > 0 and req_path.is_file():
            size = req_path.stat().st_size
            if size < min_bytes:
                warn(f'Required file too small: {req_path} ({size} bytes)')
                return False

    return True


def _check_outputs(outputs: dict[str, Any], ctx: dict[str, Any]) -> bool:
    if not outputs:
        return False

    workspace = Path(str(ctx.get('workspace', '.')))
    for value in outputs.values():
        path_value = render_template(str(value), ctx)
        out_path = Path(path_value)
        if not out_path.is_absolute():
            out_path = workspace / out_path
        if not out_path.exists():
            return False
    return True


def _resume_path(workspace: Path) -> Path:
    return workspace / 'resume.json'


def _load_resume(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {'steps': {}}
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except json.JSONDecodeError:
        return {'steps': {}}
    if not isinstance(data, dict):
        return {'steps': {}}
    if not isinstance(data.get('steps'), dict):
        data['steps'] = {}
    return data


def _save_resume(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding='utf-8')
    tmp.replace(path)


def _record_resume(
    resume_data: dict[str, Any],
    step_id: str,
    status: str,
    outputs: dict[str, Any],
    *,
    skipped: bool = False,
    message: str | None = None,
) -> None:
    entry = resume_data.setdefault('steps', {}).get(step_id, {})
    entry.update(
        {
            'status': status,
            'outputs': outputs,
            'skipped': skipped,
            'updated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        }
    )
    if message:
        entry['message'] = message
    resume_data['steps'][step_id] = entry


def _run_command(
    command: str,
    cwd: Path,
    env: dict[str, str],
    timeout: float | None,
    retries: int,
) -> bool:
    attempts = max(1, retries + 1)
    for attempt in range(1, attempts + 1):
        info(f'Running ({attempt}/{attempts}): {command}')
        try:
            result = subprocess.run(
                command,
                shell=True,
                cwd=str(cwd),
                env=env,
                timeout=timeout,
            )
        except subprocess.TimeoutExpired:
            warn(f'Timeout after {timeout}s')
            result = None

        if result is not None and result.returncode == 0:
            return True

        if result is not None:
            warn(f'Return code: {result.returncode}')

        if attempt < attempts:
            time.sleep(1)

    return False


def run_workflow(
    *,
    workflow_path: Path,
    target: str,
    out_dir: Path | None = None,
    print_plan: bool = False,
    continue_on_error: bool = False,
    var_overrides: dict[str, str] | None = None,
    resume: bool = False,
) -> None:
    workflow = load_workflow(workflow_path)
    steps = topological_order(workflow['steps'])

    if resume and out_dir is None:
        raise WorkflowError('Resume requires --out to reuse an existing workspace.')

    timestamp = time.strftime('%Y%m%d-%H%M%S')
    safe_target = re.sub(r'[^A-Za-z0-9._-]+', '_', target)
    workspace = out_dir if out_dir else Path('runs') / safe_target / timestamp
    workspace = workspace.resolve()
    workspace.mkdir(parents=True, exist_ok=True)
    resume_path = _resume_path(workspace)
    resume_data = _load_resume(resume_path) if resume else {'steps': {}}

    merged: dict[str, Any] = {}
    if isinstance(workflow.get('vars'), dict):
        merged.update(workflow.get('vars'))
    if var_overrides:
        merged.update(var_overrides)

    ctx: dict[str, Any] = dict(merged)
    ctx['vars'] = dict(merged)
    ctx['target'] = target
    ctx['workspace'] = str(workspace)
    ctx['timestamp'] = timestamp
    ctx['steps'] = {}
    ctx['status'] = {}

    if print_plan:
        info('Plan only (no execution).')

    for step in steps:
        step_id = step['id']
        info(f'Step: {step_id}')

        failed_deps = [
            dep
            for dep in step.get('depends_on', [])
            if ctx['status'].get(dep) in ('failed', 'skipped')
        ]
        if failed_deps and not step.get('run_on_failed_deps', False):
            warn(f"Skipping {step_id} due to failed deps: {', '.join(failed_deps)}")
            ctx['status'][step_id] = 'skipped'
            continue

        command = render_template(step['run'], ctx)
        outputs = {
            key: render_template(str(value), ctx)
            for key, value in (step.get('outputs') or {}).items()
        }

        existing_status = None
        if resume:
            existing_status = resume_data.get('steps', {}).get(step_id, {}).get('status')

        should_skip = False
        if step.get('skip_if_exists', False) or existing_status == 'ok':
            if step.get('requires'):
                should_skip = _check_requires(step.get('requires', []), ctx)
            else:
                should_skip = _check_outputs(outputs, ctx)

        if should_skip:
            warn(f'Skipping {step_id} (already completed)')
            ctx['steps'][step_id] = outputs
            ctx['status'][step_id] = 'skipped'
            if resume:
                _record_resume(resume_data, step_id, 'ok', outputs, skipped=True)
                _save_resume(resume_path, resume_data)
            continue
        env = os.environ.copy()
        for key, value in (step.get('env') or {}).items():
            env[key] = render_template(str(value), ctx)

        cwd_value = step.get('cwd')
        if cwd_value:
            cwd_rendered = render_template(str(cwd_value), ctx)
            cwd_path = Path(cwd_rendered)
            if not cwd_path.is_absolute():
                cwd_path = workspace / cwd_path
        else:
            cwd_path = workspace
        cwd_path.mkdir(parents=True, exist_ok=True)

        timeout_value = step.get('timeout', None)
        timeout: float | None
        if timeout_value is None:
            timeout = None
        else:
            try:
                timeout = float(timeout_value)
            except (TypeError, ValueError) as exc:
                raise WorkflowError(f"Step '{step_id}' has invalid timeout.") from exc

        if print_plan:
            print(command)
            ctx['steps'][step_id] = outputs
            ctx['status'][step_id] = 'planned'
            continue

        if resume:
            _record_resume(resume_data, step_id, 'running', outputs)
            _save_resume(resume_path, resume_data)

        _warn_missing_tool(command)
        ok = _run_command(
            command=command,
            cwd=cwd_path,
            env=env,
            timeout=timeout,
            retries=step.get('retries', 0),
        )
        ctx['steps'][step_id] = outputs
        if ok and not _check_requires(step.get('requires', []), ctx):
            ok = False

        if not ok:
            message = f'Step failed: {step_id}'
            if continue_on_error:
                warn(message + ' (continuing)')
                ctx['status'][step_id] = 'failed'
                if resume:
                    _record_resume(resume_data, step_id, 'failed', outputs, message=message)
                    _save_resume(resume_path, resume_data)
            else:
                raise WorkflowError(message)

        if ok:
            ctx['status'][step_id] = 'ok'
            if resume:
                _record_resume(resume_data, step_id, 'ok', outputs)
                _save_resume(resume_path, resume_data)

    info(f'Workspace: {workspace}')
    info('Done.')

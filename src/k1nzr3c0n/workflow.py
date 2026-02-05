from __future__ import annotations

from pathlib import Path
from concurrent.futures import ThreadPoolExecutor, as_completed
import copy
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


def load_workflow(path: Path, stack: list[Path] | None = None) -> dict[str, Any]:
    path = path.resolve()
    if stack is None:
        stack = []
    if path in stack:
        chain = ' -> '.join(str(item) for item in stack + [path])
        raise WorkflowError(f'Workflow include cycle detected: {chain}')
    if not path.exists():
        raise WorkflowError(f'Workflow not found: {path}')

    raw = path.read_text(encoding='utf-8')
    data = yaml.safe_load(raw) or {}
    if not isinstance(data, dict):
        raise WorkflowError('Workflow must be a YAML mapping at top level.')

    vars_data = data.get('vars', {})
    if vars_data is None:
        vars_data = {}
    if not isinstance(vars_data, dict):
        raise WorkflowError("Workflow 'vars' must be a mapping.")
    merged_vars = dict(vars_data)

    steps = data.get('steps')
    if not isinstance(steps, list) or not steps:
        raise WorkflowError("Workflow must contain a non-empty 'steps' list.")

    expanded_steps: list[dict[str, Any]] = []
    for idx, step in enumerate(steps, start=1):
        if not isinstance(step, dict):
            raise WorkflowError(f'Step #{idx} must be a mapping.')

        if 'workflow' in step:
            step_id = step.get('id')
            if not step_id or not isinstance(step_id, str):
                raise WorkflowError(f'Step #{idx} missing valid id.')
            if step.get('run') is not None or step.get('fanout') is not None:
                raise WorkflowError(
                    f"Step '{step_id}' cannot define run/fanout when using workflow."
                )
            workflow_path = step.get('workflow')
            if not workflow_path or not isinstance(workflow_path, str):
                raise WorkflowError(f"Step '{step_id}' missing valid workflow path.")
            namespace = step.get('namespace', step_id)
            if not namespace or not isinstance(namespace, str):
                raise WorkflowError(f"Step '{step_id}' has invalid namespace.")

            depends = step.get('depends_on', [])
            if depends is None:
                depends = []
            if isinstance(depends, str):
                depends = [depends]
            if not isinstance(depends, list) or any(
                not isinstance(x, str) for x in depends
            ):
                raise WorkflowError(f"Step '{step_id}' has invalid depends_on.")

            child_path = Path(workflow_path)
            if not child_path.is_absolute():
                child_path = path.parent / child_path
            child_data = load_workflow(child_path, stack + [path])
            child_steps = child_data.get('steps') or []

            for key, value in (child_data.get('vars') or {}).items():
                if key not in merged_vars:
                    merged_vars[key] = value

            id_map = {child['id']: f'{namespace}.{child["id"]}' for child in child_steps}

            for child in child_steps:
                new_step = copy.deepcopy(child)
                old_id = new_step['id']
                new_step['id'] = id_map[old_id]
                child_depends = new_step.get('depends_on', [])
                if child_depends is None:
                    child_depends = []
                if isinstance(child_depends, str):
                    child_depends = [child_depends]
                new_depends = [id_map.get(d, d) for d in child_depends]
                new_depends.extend(depends)
                new_step['depends_on'] = new_depends
                new_step = _rewrite_templates_in_obj(new_step, id_map)
                expanded_steps.append(new_step)
            continue

        expanded_steps.append(step)

    steps = expanded_steps
    data['vars'] = merged_vars

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

        fanout = step.get('fanout', None)
        if fanout is not None:
            if not isinstance(fanout, list) or not fanout:
                raise WorkflowError(f"Step '{step_id}' has invalid fanout.")
        run_cmd = step.get('run')
        if fanout is not None and run_cmd is not None:
            if not isinstance(run_cmd, str):
                raise WorkflowError(f"Step '{step_id}' has invalid run.")
            raise WorkflowError(
                f"Step '{step_id}' cannot define 'run' when using fanout."
            )
        if not run_cmd or not isinstance(run_cmd, str):
            if fanout is None:
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

        fanout_concurrency = step.get('fanout_concurrency', None)
        if fanout_concurrency is not None:
            try:
                fanout_concurrency = int(fanout_concurrency)
            except (TypeError, ValueError) as exc:
                raise WorkflowError(
                    f"Step '{step_id}' has invalid fanout_concurrency."
                ) from exc
            if fanout_concurrency < 1:
                raise WorkflowError(
                    f"Step '{step_id}' fanout_concurrency must be >= 1."
                )
        step['fanout_concurrency'] = fanout_concurrency

        fanout_timeout_default = step.get('fanout_timeout_default', None)
        if fanout_timeout_default is not None and not isinstance(
            fanout_timeout_default, (int, float, str)
        ):
            raise WorkflowError(
                f"Step '{step_id}' has invalid fanout_timeout_default."
            )
        step['fanout_timeout_default'] = fanout_timeout_default

        if fanout is not None:
            child_seen: set[str] = set()
            normalized_fanout: list[dict[str, Any]] = []
            for child_idx, child in enumerate(fanout, start=1):
                if not isinstance(child, dict):
                    raise WorkflowError(
                        f"Step '{step_id}' fanout item #{child_idx} must be a mapping."
                    )
                child_id = child.get('id')
                if not child_id or not isinstance(child_id, str):
                    raise WorkflowError(
                        f"Step '{step_id}' fanout item #{child_idx} missing valid id."
                    )
                if child_id in child_seen:
                    raise WorkflowError(
                        f"Step '{step_id}' fanout duplicate id: {child_id}"
                    )
                child_seen.add(child_id)

                child_run = child.get('run')
                if not child_run or not isinstance(child_run, str):
                    raise WorkflowError(
                        f"Step '{step_id}' fanout '{child_id}' missing valid run."
                    )
                if child.get('depends_on') is not None:
                    raise WorkflowError(
                        f"Step '{step_id}' fanout '{child_id}' cannot use depends_on."
                    )
                child['depends_on'] = []

                retries = child.get('retries', 0)
                if retries is None:
                    retries = 0
                try:
                    child['retries'] = int(retries)
                except (TypeError, ValueError) as exc:
                    raise WorkflowError(
                        f"Step '{step_id}' fanout '{child_id}' has invalid retries."
                    ) from exc

                skip_if_exists = child.get('skip_if_exists', False)
                if not isinstance(skip_if_exists, bool):
                    raise WorkflowError(
                        f"Step '{step_id}' fanout '{child_id}' has invalid skip_if_exists."
                    )
                child['skip_if_exists'] = skip_if_exists

                run_on_failed_deps = child.get('run_on_failed_deps', False)
                if not isinstance(run_on_failed_deps, bool):
                    raise WorkflowError(
                        f"Step '{step_id}' fanout '{child_id}' has invalid run_on_failed_deps."
                    )
                child['run_on_failed_deps'] = run_on_failed_deps

                requires = child.get('requires', [])
                if requires is None:
                    requires = []
                if isinstance(requires, (str, dict)):
                    requires = [requires]
                if not isinstance(requires, list):
                    raise WorkflowError(
                        f"Step '{step_id}' fanout '{child_id}' has invalid requires."
                    )
                normalized_child: list[dict[str, Any]] = []
                for item in requires:
                    if isinstance(item, str):
                        normalized_child.append({'path': item, 'min_bytes': 0})
                        continue
                    if isinstance(item, dict):
                        path_value = item.get('path')
                        if not path_value or not isinstance(path_value, str):
                            raise WorkflowError(
                                f"Step '{step_id}' fanout '{child_id}' requires entries "
                                "must include string path."
                            )
                        min_bytes = item.get('min_bytes', 0)
                        if min_bytes is None:
                            min_bytes = 0
                        try:
                            min_bytes = int(min_bytes)
                        except (TypeError, ValueError) as exc:
                            raise WorkflowError(
                                f"Step '{step_id}' fanout '{child_id}' has invalid requires.min_bytes."
                            ) from exc
                        normalized_child.append({'path': path_value, 'min_bytes': min_bytes})
                        continue
                    raise WorkflowError(
                        f"Step '{step_id}' fanout '{child_id}' has invalid requires entry."
                    )
                child['requires'] = normalized_child

                normalized_fanout.append(child)
            step['fanout'] = normalized_fanout

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


def _parse_timeout(value: Any, *, label: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        timeout = float(value)
    elif isinstance(value, str):
        raw = value.strip().lower()
        if not raw:
            return None
        unit = raw[-1]
        if unit in ('s', 'm', 'h'):
            num = raw[:-1].strip()
        else:
            unit = ''
            num = raw
        try:
            timeout = float(num)
        except ValueError as exc:
            raise WorkflowError(f'{label} has invalid timeout.') from exc
        if unit == 'm':
            timeout *= 60
        elif unit == 'h':
            timeout *= 3600
    else:
        raise WorkflowError(f'{label} has invalid timeout type.')

    if timeout <= 0:
        raise WorkflowError(f'{label} timeout must be > 0.')
    return timeout


def _set_step_outputs(ctx: dict[str, Any], step_id: str, outputs: Any) -> None:
    current = ctx.setdefault('steps', {})
    parts = step_id.split('.')
    for part in parts[:-1]:
        node = current.get(part)
        if not isinstance(node, dict):
            node = {}
            current[part] = node
        current = node
    current[parts[-1]] = outputs


def _ensure_step_container(ctx: dict[str, Any], step_id: str) -> dict[str, Any]:
    current = ctx.setdefault('steps', {})
    parts = step_id.split('.')
    for part in parts:
        node = current.get(part)
        if not isinstance(node, dict):
            node = {}
            current[part] = node
        current = node
    return current


def _rewrite_step_refs_in_str(text: str, id_map: dict[str, str]) -> str:
    if not id_map:
        return text
    keys = sorted(id_map.keys(), key=len, reverse=True)
    for key in keys:
        text = text.replace(f'{{steps.{key}.', f'{{steps.{id_map[key]}.')
    return text


def _rewrite_templates_in_obj(value: Any, id_map: dict[str, str]) -> Any:
    if isinstance(value, str):
        return _rewrite_step_refs_in_str(value, id_map)
    if isinstance(value, list):
        return [_rewrite_templates_in_obj(item, id_map) for item in value]
    if isinstance(value, dict):
        return {key: _rewrite_templates_in_obj(val, id_map) for key, val in value.items()}
    return value


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

        fanout = step.get('fanout')
        if fanout:
            fanout_container = _ensure_step_container(ctx, step_id)

            if print_plan:
                for child in fanout:
                    child_id = child['id']
                    child_outputs = {
                        key: render_template(str(value), ctx)
                        for key, value in (child.get('outputs') or {}).items()
                    }
                    fanout_container[child_id] = child_outputs
                    child_cmd = render_template(child['run'], ctx)
                    print(f'{step_id}.{child_id}: {child_cmd}')
                ctx['status'][step_id] = 'planned'
                continue

            tasks: list[dict[str, Any]] = []
            for child in fanout:
                child_id = child['id']
                composite_id = f'{step_id}.{child_id}'
                child_outputs = {
                    key: render_template(str(value), ctx)
                    for key, value in (child.get('outputs') or {}).items()
                }
                fanout_container[child_id] = child_outputs

                existing_status = None
                if resume:
                    existing_status = (
                        resume_data.get('steps', {}).get(composite_id, {}).get('status')
                    )

                should_skip = False
                if child.get('skip_if_exists', False) or existing_status == 'ok':
                    if child.get('requires'):
                        should_skip = _check_requires(child.get('requires', []), ctx)
                    else:
                        should_skip = _check_outputs(child_outputs, ctx)

                if should_skip:
                    warn(f'Skipping {composite_id} (already completed)')
                    ctx['status'][composite_id] = 'skipped'
                    if resume:
                        _record_resume(
                            resume_data,
                            composite_id,
                            'ok',
                            child_outputs,
                            skipped=True,
                        )
                        _save_resume(resume_path, resume_data)
                    continue

                command = render_template(child['run'], ctx)
                _warn_missing_tool(command)
                env = os.environ.copy()
                for key, value in (child.get('env') or {}).items():
                    env[key] = render_template(str(value), ctx)

                cwd_value = child.get('cwd')
                if cwd_value:
                    cwd_rendered = render_template(str(cwd_value), ctx)
                    cwd_path = Path(cwd_rendered)
                    if not cwd_path.is_absolute():
                        cwd_path = workspace / cwd_path
                else:
                    cwd_path = workspace
                cwd_path.mkdir(parents=True, exist_ok=True)

                timeout_value = child.get('timeout', None)
                if timeout_value is None:
                    timeout_value = step.get('fanout_timeout_default', None)
                timeout = _parse_timeout(
                    timeout_value,
                    label=f"Step '{step_id}' fanout '{child_id}'",
                )

                tasks.append(
                    {
                        'key': composite_id,
                        'command': command,
                        'env': env,
                        'cwd': cwd_path,
                        'timeout': timeout,
                        'retries': child.get('retries', 0),
                        'requires': child.get('requires', []),
                        'outputs': child_outputs,
                    }
                )

            if not tasks:
                ctx['status'][step_id] = 'skipped'
                if resume:
                    _record_resume(resume_data, step_id, 'ok', {}, skipped=True)
                    _save_resume(resume_path, resume_data)
                continue

            if resume:
                for task in tasks:
                    _record_resume(resume_data, task['key'], 'running', task['outputs'])
                _save_resume(resume_path, resume_data)

            max_workers = step.get('fanout_concurrency') or min(len(tasks), 4)
            failed_items: list[str] = []
            with ThreadPoolExecutor(max_workers=max_workers) as executor:
                futures = {
                    executor.submit(
                        _run_command,
                        task['command'],
                        task['cwd'],
                        task['env'],
                        task['timeout'],
                        task['retries'],
                    ): task
                    for task in tasks
                }
                for future in as_completed(futures):
                    task = futures[future]
                    ok = future.result()
                    if ok and not _check_requires(task['requires'], ctx):
                        ok = False

                    if ok:
                        ctx['status'][task['key']] = 'ok'
                        if resume:
                            _record_resume(resume_data, task['key'], 'ok', task['outputs'])
                    else:
                        ctx['status'][task['key']] = 'failed'
                        failed_items.append(task['key'])
                        if resume:
                            _record_resume(
                                resume_data,
                                task['key'],
                                'failed',
                                task['outputs'],
                                message=f'Failed: {task["key"]}',
                            )
                    if resume:
                        _save_resume(resume_path, resume_data)

            if failed_items:
                ctx['status'][step_id] = 'failed'
                if resume:
                    _record_resume(
                        resume_data,
                        step_id,
                        'failed',
                        {},
                        message=f'Fanout failed: {", ".join(failed_items)}',
                    )
                    _save_resume(resume_path, resume_data)
                if not continue_on_error:
                    raise WorkflowError(
                        f"Fanout step failed: {step_id} ({', '.join(failed_items)})"
                    )
            else:
                ctx['status'][step_id] = 'ok'
                if resume:
                    _record_resume(resume_data, step_id, 'ok', {})
                    _save_resume(resume_path, resume_data)

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
            _set_step_outputs(ctx, step_id, outputs)
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
        timeout = _parse_timeout(timeout_value, label=f"Step '{step_id}'")

        if print_plan:
            print(command)
            _set_step_outputs(ctx, step_id, outputs)
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
        _set_step_outputs(ctx, step_id, outputs)
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

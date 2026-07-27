"""k1nzr3c0n workflow engine.

Execution model
---------------
* load_workflow()      — parse + validate YAML, inline included sub-workflows
* topological_order()  — Kahn's algorithm; raises on cycles
* _execution_levels()  — BFS grouping; all steps in one level are independent
* run_workflow()       — iterate levels; within each level run concurrently via ThreadPoolExecutor

Thread-safety
-------------
_RunState.ctx_lock guards all writes to the shared execution context (status dict and step
outputs).  Reads are safe without locking because they only access keys that were fully written
before the parallel section started (target, workspace, vars, completed step outputs).
"""
from __future__ import annotations

import copy
import json
import os
import re
import shlex
import shutil
import signal
import subprocess
import sys
import tempfile
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# Exit code used to signal a clean pause (EX_TEMPFAIL). The Celery task
# detects this and sets run status to "paused" instead of "failed".
PAUSE_EXIT_CODE = 75


# ── Public exception ──────────────────────────────────────────────────────────

class WorkflowError(RuntimeError):
    pass


# ── Template engine ───────────────────────────────────────────────────────────

_PLACEHOLDER = re.compile(r'\{([A-Za-z0-9_.|-]+)\}')


def _resolve_key(key: str, ctx: dict[str, Any]) -> Any:
    """Resolve a dotted key path like `steps.httpx.file` against ctx."""
    current: Any = ctx
    for part in key.split('.'):
        if isinstance(current, dict) and part in current:
            current = current[part]
        else:
            return None
    return current


def render_template(template: str, ctx: dict[str, Any], *, allow_missing: bool = False) -> str:
    """Substitute {key} and {key|default} placeholders.

    Supports:
      {target}           — simple key
      {vars.wordlist}    — dotted path
      {steps.sub.file}  — nested step output
      {key|default}      — literal fallback when key is missing or empty
    """
    if not isinstance(template, str):
        return template

    def repl(match: re.Match[str]) -> str:
        spec = match.group(1)
        if '|' in spec:
            key, default = spec.split('|', 1)
            value = _resolve_key(key.strip(), ctx)
            return str(value) if value is not None else default
        value = _resolve_key(spec, ctx)
        if value is None:
            if allow_missing:
                return match.group(0)
            raise WorkflowError(f"Unknown template variable: '{spec}'")
        return str(value)

    return _PLACEHOLDER.sub(repl, template)


# ── Shared runner state ───────────────────────────────────────────────────────

@dataclass
class _RunState:
    """All mutable state for one run_workflow() invocation.

    Passed explicitly to sub-functions instead of captured in closures,
    making the data-flow visible and unit-testable.
    """
    ctx: dict[str, Any]
    workspace: Path
    resume: bool
    resume_data: dict[str, Any]
    resume_path: Path
    print_plan: bool
    continue_on_error: bool
    ctx_lock: threading.Lock = field(default_factory=threading.Lock)
    resume_lock: threading.Lock = field(default_factory=threading.Lock)

    def set_status(self, step_id: str, status: str) -> None:
        with self.ctx_lock:
            self.ctx['status'][step_id] = status

    def get_status(self, step_id: str) -> str | None:
        return self.ctx['status'].get(step_id)

    def set_outputs(self, step_id: str, outputs: dict[str, Any]) -> None:
        with self.ctx_lock:
            _set_step_outputs(self.ctx, step_id, outputs)


# ── Logging ───────────────────────────────────────────────────────────────────

_PRINT_LOCK = threading.Lock()


def info(message: str) -> None:
    with _PRINT_LOCK:
        print(f'[+] {message}', flush=True)


def warn(message: str) -> None:
    with _PRINT_LOCK:
        print(f'[!] {message}', flush=True)


# ── Workflow loading + validation ─────────────────────────────────────────────

def parse_var_overrides(items: list[str]) -> dict[str, str]:
    overrides: dict[str, str] = {}
    for item in items:
        if '=' not in item:
            raise WorkflowError(f'Invalid --vars entry: {item!r}. Expected key=value.')
        key, value = item.split('=', 1)
        key = key.strip()
        if not key:
            raise WorkflowError('Invalid --vars entry: empty key.')
        overrides[key] = value
    return overrides


def _normalize_requires(requires: Any, label: str) -> list[dict[str, Any]]:
    if requires is None:
        return []
    if isinstance(requires, (str, dict)):
        requires = [requires]
    if not isinstance(requires, list):
        raise WorkflowError(f"{label}: 'requires' must be a list.")
    result: list[dict[str, Any]] = []
    for item in requires:
        if isinstance(item, str):
            result.append({'path': item, 'min_bytes': 0})
            continue
        if isinstance(item, dict):
            path_val = item.get('path')
            if not path_val or not isinstance(path_val, str):
                raise WorkflowError(f"{label}: requires entries must have a string 'path'.")
            mb = item.get('min_bytes', 0)
            try:
                result.append({'path': path_val, 'min_bytes': int(mb if mb is not None else 0)})
            except (TypeError, ValueError):
                raise WorkflowError(f"{label}: requires.min_bytes must be an integer.")
            continue
        raise WorkflowError(f"{label}: invalid requires entry type.")
    return result


def _normalize_step_common(step: dict[str, Any], label: str) -> None:
    """Validate and normalise fields shared by both regular steps and fanout children."""
    retries = step.get('retries', 0)
    try:
        step['retries'] = int(retries if retries is not None else 0)
    except (TypeError, ValueError):
        raise WorkflowError(f"{label}: 'retries' must be an integer.")

    for bool_field in ('skip_if_exists', 'run_on_failed_deps', 'optional'):
        v = step.get(bool_field, False)
        if not isinstance(v, bool):
            raise WorkflowError(f"{label}: '{bool_field}' must be a boolean.")
        step[bool_field] = v

    step['requires'] = _normalize_requires(step.get('requires'), label)


def load_workflow(path: Path, stack: list[Path] | None = None) -> dict[str, Any]:
    """Parse, validate, and flatten a workflow YAML (recursively inlining sub-workflows)."""
    path = path.resolve()
    if stack is None:
        stack = []
    if path in stack:
        chain = ' → '.join(str(p) for p in stack + [path])
        raise WorkflowError(f'Workflow include cycle: {chain}')
    if not path.exists():
        raise WorkflowError(f'Workflow not found: {path}')

    data = yaml.safe_load(path.read_text(encoding='utf-8')) or {}
    if not isinstance(data, dict):
        raise WorkflowError('Workflow must be a YAML mapping at top level.')

    vars_data = data.get('vars') or {}
    if not isinstance(vars_data, dict):
        raise WorkflowError("'vars' must be a mapping.")
    merged_vars: dict[str, Any] = dict(vars_data)

    raw_steps = data.get('steps')
    if not isinstance(raw_steps, list) or not raw_steps:
        raise WorkflowError("Workflow must contain a non-empty 'steps' list.")

    # ── Phase 1: inline included sub-workflows ─────────────────────────────────
    expanded: list[dict[str, Any]] = []
    for idx, step in enumerate(raw_steps, start=1):
        if not isinstance(step, dict):
            raise WorkflowError(f'Step #{idx} must be a mapping.')
        if 'workflow' not in step:
            expanded.append(step)
            continue

        step_id = step.get('id')
        if not step_id or not isinstance(step_id, str):
            raise WorkflowError(f'Step #{idx} (workflow include): missing valid id.')
        if step.get('run') is not None or step.get('fanout') is not None:
            raise WorkflowError(f"Step '{step_id}': cannot mix workflow include with run/fanout.")

        wf_ref = step['workflow']
        namespace = step.get('namespace', step_id)
        depends = _coerce_list(step.get('depends_on', []), f"Step '{step_id}' depends_on")

        child_path = Path(wf_ref)
        if not child_path.is_absolute():
            # Try CWD first (allows `workflow: workflows/foo.yaml` from anywhere),
            # then fall back to relative to the including file's directory.
            candidate_cwd = Path.cwd() / child_path
            candidate_rel = path.parent / child_path
            child_path = candidate_cwd if candidate_cwd.exists() else candidate_rel
        child_data = load_workflow(child_path, stack + [path])

        for k, v in (child_data.get('vars') or {}).items():
            if k not in merged_vars:
                merged_vars[k] = v

        child_steps = child_data.get('steps') or []
        id_map = {c['id']: f'{namespace}.{c["id"]}' for c in child_steps}

        for child in child_steps:
            ns_step = copy.deepcopy(child)
            ns_step['id'] = id_map[ns_step['id']]
            child_deps = _coerce_list(ns_step.get('depends_on', []), f"Child step depends_on")
            ns_step['depends_on'] = [id_map.get(d, d) for d in child_deps] + depends
            ns_step = _rewrite_templates_in_obj(ns_step, id_map)
            expanded.append(ns_step)

    # ── Phase 2: validate every expanded step ──────────────────────────────────
    seen_ids: set[str] = set()
    for idx, step in enumerate(expanded, start=1):
        if not isinstance(step, dict):
            raise WorkflowError(f'Step #{idx} must be a mapping.')
        step_id = step.get('id')
        if not step_id or not isinstance(step_id, str):
            raise WorkflowError(f'Step #{idx}: missing valid id.')
        if step_id in seen_ids:
            raise WorkflowError(f"Duplicate step id: '{step_id}'")
        seen_ids.add(step_id)

        label = f"Step '{step_id}'"
        step['depends_on'] = _coerce_list(step.get('depends_on', []), f"{label} depends_on")
        _normalize_step_common(step, label)

        fanout = step.get('fanout')
        run_cmd = step.get('run')
        when = step.get('when')

        if fanout is not None:
            if run_cmd is not None:
                raise WorkflowError(f"{label}: cannot define both 'run' and 'fanout'.")
            if not isinstance(fanout, list) or not fanout:
                raise WorkflowError(f"{label}: 'fanout' must be a non-empty list.")
            _validate_fanout(step, label)
        elif run_cmd is None and when is None:
            raise WorkflowError(f"{label}: missing 'run' (and no 'fanout').")
        elif run_cmd is not None and not isinstance(run_cmd, str):
            raise WorkflowError(f"{label}: 'run' must be a string.")

        step['when'] = when  # may be None

        fc = step.get('fanout_concurrency')
        if fc is not None:
            try:
                fc = int(fc)
            except (TypeError, ValueError):
                raise WorkflowError(f"{label}: 'fanout_concurrency' must be an integer.")
            if fc < 1:
                raise WorkflowError(f"{label}: 'fanout_concurrency' must be >= 1.")
        step['fanout_concurrency'] = fc
        step['fanout_timeout_default'] = step.get('fanout_timeout_default')

    data['vars'] = merged_vars
    data['steps'] = expanded
    return data


def _validate_fanout(step: dict[str, Any], parent_label: str) -> None:
    child_seen: set[str] = set()
    normalized: list[dict[str, Any]] = []
    for ci, child in enumerate(step['fanout'], start=1):
        if not isinstance(child, dict):
            raise WorkflowError(f"{parent_label} fanout #{ci}: must be a mapping.")
        child_id = child.get('id')
        if not child_id or not isinstance(child_id, str):
            raise WorkflowError(f"{parent_label} fanout #{ci}: missing valid id.")
        if child_id in child_seen:
            raise WorkflowError(f"{parent_label} fanout: duplicate id '{child_id}'.")
        child_seen.add(child_id)
        if child.get('depends_on') is not None:
            raise WorkflowError(f"{parent_label} fanout '{child_id}': cannot use depends_on.")
        child_run = child.get('run')
        if not child_run or not isinstance(child_run, str):
            raise WorkflowError(f"{parent_label} fanout '{child_id}': missing valid run.")
        child['depends_on'] = []
        _normalize_step_common(child, f"{parent_label} fanout '{child_id}'")
        normalized.append(child)
    step['fanout'] = normalized


# ── Topology helpers ──────────────────────────────────────────────────────────

def topological_order(steps: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Kahn's algorithm. Raises WorkflowError on cycles or missing dependencies."""
    by_id = {s['id']: s for s in steps}
    index = {s['id']: i for i, s in enumerate(steps)}

    for sid, step in by_id.items():
        missing = [d for d in step.get('depends_on', []) if d not in by_id]
        if missing:
            raise WorkflowError(f"Step '{sid}' depends on unknown step(s): {', '.join(missing)}")

    deps = {sid: set(by_id[sid].get('depends_on', [])) for sid in by_id}
    ready = sorted([s for s, d in deps.items() if not d], key=lambda s: index[s])
    order: list[str] = []

    while ready:
        sid = ready.pop(0)
        order.append(sid)
        for other, ds in deps.items():
            if sid in ds:
                ds.discard(sid)
                if not ds and other not in order and other not in ready:
                    ready.append(other)
                    ready.sort(key=lambda s: index[s])

    if len(order) != len(by_id):
        raise WorkflowError('Dependency cycle detected in workflow steps.')

    return [by_id[sid] for sid in order]


def _execution_levels(ordered: list[dict[str, Any]]) -> list[list[dict[str, Any]]]:
    """Assign each step to the earliest parallel level it can run in."""
    level_of: dict[str, int] = {}
    for step in ordered:
        deps = step.get('depends_on', [])
        level_of[step['id']] = (max(level_of.get(d, 0) for d in deps) + 1) if deps else 0

    if not level_of:
        return []
    levels: list[list[dict[str, Any]]] = [[] for _ in range(max(level_of.values()) + 1)]
    for step in ordered:
        levels[level_of[step['id']]].append(step)
    return levels


# ── Machine-readable step event markers ──────────────────────────────────────

def _step_event(event: str, step_id: str, **extra: Any) -> None:
    """Emit a machine-readable step marker parsed by tasks.py.

    Format: ##K1Z:EVENT:step_id[:value...]##
    Examples:
      ##K1Z:START:subfinder##
      ##K1Z:DONE:subfinder##
      ##K1Z:TIME:subfinder:4217##   (ms)
    """
    extras = ''.join(f':{v}' for v in extra.values()) if extra else ''
    with _PRINT_LOCK:
        print(f'##K1Z:{event}:{step_id}{extras}##', flush=True)


# ── Process management ────────────────────────────────────────────────────────

def _kill_proc(proc: subprocess.Popen) -> None:
    """SIGTERM process group, then SIGKILL if it doesn't die within 5 s."""
    try:
        pgid = os.getpgid(proc.pid)
        os.killpg(pgid, signal.SIGTERM)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            proc.kill()
        except ProcessLookupError:
            pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        try:
            proc.kill()
            proc.wait()
        except Exception:
            pass


def _warn_missing_tool(command: str) -> None:
    try:
        parts = shlex.split(command, posix=os.name != 'nt')
    except ValueError:
        return
    if parts and shutil.which(parts[0]) is None:
        warn(f'Tool not found in PATH: {parts[0]}')


def _run_command(
    command: str,
    cwd: Path,
    env: dict[str, str],
    timeout: float | None,
    retries: int,
    label: str = '',
    shell: bool = False,
) -> bool:
    """Stream command output, handle timeout and retries.

    Returns True only if the command exits with code 0.
    """
    script_path: str | None = None

    if shell:
        command = command.strip()
        if '\n' in command:
            # Write multiline scripts to a temp file so the shell executes them
            # exactly as written — avoids any quoting or newline-collapsing issues.
            fd, script_path = tempfile.mkstemp(suffix='.sh', prefix='k1z_')
            with os.fdopen(fd, 'w') as fh:
                fh.write('#!/bin/bash\n')
                fh.write(command)
                fh.write('\n')
            os.chmod(script_path, 0o755)
        popen_args = script_path or command
        use_shell = script_path is None  # file is directly executable; no shell wrapper needed
    else:
        try:
            parts = shlex.split(command, posix=os.name != 'nt')
        except ValueError as exc:
            warn(f'[{label}] Invalid command syntax: {exc}')
            return False
        if not parts:
            return False
        popen_args = parts
        use_shell = False

    pfx = f'[{label}] '
    attempts = max(1, retries + 1)

    try:
      for attempt in range(1, attempts + 1):
        info(f'{pfx}({attempt}/{attempts}) {command}')
        t_start = time.monotonic()
        deadline = t_start + timeout if timeout else None
        timed_out = False

        try:
            proc = subprocess.Popen(
                popen_args,
                shell=use_shell,
                cwd=str(cwd),
                env=env,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                start_new_session=True,
            )
        except FileNotFoundError:
            warn(f'{pfx}Tool not found: {command.split()[0]}')
            return False
        except OSError as exc:
            warn(f'{pfx}OS error: {exc}')
            return False

        try:
            for line in proc.stdout:
                print(f'{pfx}{line}', end='', flush=True)
                if deadline and time.monotonic() > deadline:
                    timed_out = True
                    break
        finally:
            if timed_out or proc.poll() is None:
                _kill_proc(proc)
            else:
                proc.wait()

        elapsed_s = time.monotonic() - t_start

        if timed_out:
            warn(f'{pfx}Timed out after {timeout:.0f}s')
            if attempt < attempts:
                time.sleep(1)
            continue

        if proc.returncode == 0:
            info(f'{pfx}Done ({elapsed_s:.1f}s)')
            return True

        warn(f'{pfx}Exit code {proc.returncode} ({elapsed_s:.1f}s)')
        if attempt < attempts:
            time.sleep(1)

      return False
    finally:
        if script_path:
            try:
                os.unlink(script_path)
            except OSError:
                pass


# ── Resume / checkpoint ───────────────────────────────────────────────────────

def _pause_flag_path(workspace: Path) -> Path:
    return workspace / 'pause.flag'


def _check_pause_flag(workspace: Path) -> bool:
    return _pause_flag_path(workspace).exists()


def _resume_path(workspace: Path) -> Path:
    return workspace / 'resume.json'


def _load_resume(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {'steps': {}}
    try:
        data = json.loads(path.read_text(encoding='utf-8'))
    except json.JSONDecodeError:
        return {'steps': {}}
    if not isinstance(data, dict) or not isinstance(data.get('steps'), dict):
        return {'steps': {}}
    return data


def _save_resume(path: Path, data: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix('.tmp')
    tmp.write_text(json.dumps(data, indent=2, sort_keys=True), encoding='utf-8')
    tmp.replace(path)


def _record_resume(
    state: _RunState,
    step_id: str,
    status: str,
    outputs: dict[str, Any],
    *,
    skipped: bool = False,
    message: str | None = None,
) -> None:
    with state.resume_lock:
        entry = state.resume_data.setdefault('steps', {}).get(step_id, {})
        entry.update({
            'status': status,
            'outputs': outputs,
            'skipped': skipped,
            'updated_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        })
        if message:
            entry['message'] = message
        state.resume_data['steps'][step_id] = entry
        _save_resume(state.resume_path, state.resume_data)


# ── Requires / output checks ──────────────────────────────────────────────────

def _check_requires(requires: list[dict[str, Any]], ctx: dict[str, Any], *, quiet: bool = False) -> bool:
    workspace = Path(str(ctx.get('workspace', '.')))
    for req in requires:
        raw_path = render_template(str(req['path']), ctx)
        p = Path(raw_path)
        if not p.is_absolute():
            p = workspace / p
        if not p.exists():
            if not quiet:
                warn(f'Required path missing: {p}')
            return False
        min_b = int(req.get('min_bytes', 0))
        if min_b > 0 and p.is_file() and p.stat().st_size < min_b:
            if not quiet:
                warn(f'Required file too small: {p} ({p.stat().st_size} < {min_b} bytes)')
            return False
    return True


def _check_outputs(outputs: dict[str, Any], ctx: dict[str, Any]) -> bool:
    workspace = Path(str(ctx.get('workspace', '.')))
    for value in outputs.values():
        p = Path(render_template(str(value), ctx))
        if not p.is_absolute():
            p = workspace / p
        if not p.exists():
            return False
    return True


# ── Context helpers (called under ctx_lock) ───────────────────────────────────

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
    for part in step_id.split('.'):
        node = current.get(part)
        if not isinstance(node, dict):
            node = {}
            current[part] = node
        current = node
    return current


# ── Template rewriting (for namespaced includes) ──────────────────────────────

def _rewrite_step_refs(text: str, id_map: dict[str, str]) -> str:
    for old_id, new_id in sorted(id_map.items(), key=lambda x: -len(x[0])):
        text = text.replace(f'{{steps.{old_id}.', f'{{steps.{new_id}.')
    return text


def _rewrite_templates_in_obj(value: Any, id_map: dict[str, str]) -> Any:
    if isinstance(value, str):
        return _rewrite_step_refs(value, id_map)
    if isinstance(value, list):
        return [_rewrite_templates_in_obj(item, id_map) for item in value]
    if isinstance(value, dict):
        return {k: _rewrite_templates_in_obj(v, id_map) for k, v in value.items()}
    return value


# ── Misc ──────────────────────────────────────────────────────────────────────

def _coerce_list(value: Any, label: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [value]
    if isinstance(value, list) and all(isinstance(x, str) for x in value):
        return value
    raise WorkflowError(f"{label}: must be a string or list of strings.")


def _parse_timeout(value: Any, *, label: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, (int, float)):
        t = float(value)
    elif isinstance(value, str):
        raw = value.strip().lower()
        if not raw:
            return None
        unit = raw[-1] if raw[-1] in ('s', 'm', 'h') else ''
        num = raw[:-1] if unit else raw
        try:
            t = float(num)
        except ValueError:
            raise WorkflowError(f"{label}: invalid timeout '{value}'.")
        t *= {'m': 60, 'h': 3600}.get(unit, 1)
    else:
        raise WorkflowError(f"{label}: timeout must be a number or string.")
    if t <= 0:
        raise WorkflowError(f"{label}: timeout must be > 0.")
    return t


_FALSY = ('', '0', 'false', 'no', 'none')


def _eval_when(when_expr: str, ctx: dict[str, Any]) -> bool:
    """Evaluate a `when:` expression.

    Supports `&&` (all parts must be truthy) and `||` (any part must be truthy).
    A rendered part is falsy when it is: empty, '0', 'false', 'no', or 'none'.

    Examples:
        when: '{vars.run_discovery}'
        when: '{vars.run_discovery} && {vars.chaos_key}'
        when: '{vars.run_fast} || {vars.run_deep}'
    """
    # OR  — any truthy part passes
    if '||' in when_expr:
        return any(
            render_template(p.strip(), ctx, allow_missing=True).strip().lower() not in _FALSY
            for p in when_expr.split('||')
        )
    # AND — all parts must be truthy
    return all(
        render_template(p.strip(), ctx, allow_missing=True).strip().lower() not in _FALSY
        for p in when_expr.split('&&')
    )


# ── Step execution ────────────────────────────────────────────────────────────

def _make_env(step: dict[str, Any], ctx: dict[str, Any]) -> dict[str, str]:
    env = os.environ.copy()
    for k, v in (step.get('env') or {}).items():
        env[k] = render_template(str(v), ctx)
    return env


def _resolve_cwd(step: dict[str, Any], ctx: dict[str, Any], workspace: Path) -> Path:
    cwd_val = step.get('cwd')
    if cwd_val:
        cwd = Path(render_template(str(cwd_val), ctx))
        if not cwd.is_absolute():
            cwd = workspace / cwd
    else:
        cwd = workspace
    cwd.mkdir(parents=True, exist_ok=True)
    return cwd


def _execute_fanout(step: dict[str, Any], state: _RunState) -> str:
    """Execute a fanout step (parallel sub-commands within one step).

    Returns 'ok', 'failed', or 'skipped'.
    """
    step_id = step['id']
    ctx = state.ctx
    workspace = state.workspace

    with state.ctx_lock:
        fanout_container = _ensure_step_container(ctx, step_id)

    # Resolve all sub-tasks, skipping any that are already done
    tasks: list[dict[str, Any]] = []
    for child in step['fanout']:
        child_id = child['id']
        composite_id = f'{step_id}.{child_id}'
        child_outputs = {
            k: render_template(str(v), ctx)
            for k, v in (child.get('outputs') or {}).items()
        }
        with state.ctx_lock:
            fanout_container[child_id] = child_outputs

        # when: condition on fanout child
        child_when = child.get('when')
        if child_when is not None and not _eval_when(child_when, ctx):
            info(f'Skipping {composite_id} (when condition false)')
            state.set_status(composite_id, 'skipped')
            continue

        # Resume / skip-if-exists check
        existing_status = (
            state.resume_data.get('steps', {}).get(composite_id, {}).get('status')
            if state.resume else None
        )
        should_skip = (child.get('skip_if_exists') or existing_status == 'ok')
        if should_skip:
            cond = _check_requires(child['requires'], ctx, quiet=True) if child['requires'] else _check_outputs(child_outputs, ctx)
            if cond:
                warn(f'Skipping {composite_id} (already completed)')
                state.set_status(composite_id, 'skipped')
                if state.resume:
                    _record_resume(state, composite_id, 'ok', child_outputs, skipped=True)
                continue

        command = render_template(child['run'], ctx)
        use_shell = bool(child.get('shell', False))
        if not use_shell:
            _warn_missing_tool(command)

        timeout_val = child.get('timeout') or step.get('fanout_timeout_default')
        tasks.append({
            'key': composite_id,
            'child_id': child_id,
            'command': command,
            'env': _make_env(child, ctx),
            'cwd': _resolve_cwd(child, ctx, workspace),
            'timeout': _parse_timeout(timeout_val, label=f"Step '{composite_id}'"),
            'retries': child.get('retries', 0),
            'requires': child['requires'],
            'outputs': child_outputs,
            'shell': use_shell,
            'optional': bool(child.get('optional', False)),
        })

    if not tasks:
        state.set_status(step_id, 'skipped')
        _step_event('SKIP', step_id)
        if state.resume:
            _record_resume(state, step_id, 'ok', {}, skipped=True)
        return 'skipped'

    if state.resume:
        for task in tasks:
            _record_resume(state, task['key'], 'running', task['outputs'])

    max_workers = step.get('fanout_concurrency') or min(len(tasks), 4)
    failed: list[str] = []

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {
            pool.submit(
                _run_command,
                task['command'],
                task['cwd'],
                task['env'],
                task['timeout'],
                task['retries'],
                f'{step_id}.{task["child_id"]}',
                task['shell'],
            ): task
            for task in tasks
        }
        for future in as_completed(futures):
            task = futures[future]
            ok = future.result()
            if ok and task['requires'] and not _check_requires(task['requires'], ctx):
                ok = False
            if not ok and task.get('optional'):
                warn(f"Fanout item {task['key']} failed but is optional, continuing.")
                ok = True
            state.set_status(task['key'], 'ok' if ok else 'failed')
            if state.resume:
                _record_resume(state, task['key'], 'ok' if ok else 'failed', task['outputs'],
                               message=None if ok else f"Failed: {task['key']}")
            if not ok:
                failed.append(task['key'])

    result_status = 'failed' if failed else 'ok'
    state.set_status(step_id, result_status)
    _step_event('FAIL' if failed else 'DONE', step_id)
    if state.resume:
        _record_resume(state, step_id, result_status, {},
                       message=f'Fanout failed: {", ".join(failed)}' if failed else None)
    return result_status


def _execute_step(step: dict[str, Any], state: _RunState) -> str:
    """Execute one workflow step. Thread-safe. Returns 'ok', 'failed', or 'skipped'."""
    step_id = step['id']
    ctx = state.ctx

    # ── Check failed dependencies ──────────────────────────────────────────────
    failed_deps = [
        d for d in step.get('depends_on', [])
        if state.get_status(d) in ('failed', 'skipped')
    ]
    if failed_deps and not step.get('run_on_failed_deps'):
        warn(f"Skipping '{step_id}' (failed deps: {', '.join(failed_deps)})")
        _step_event('SKIP', step_id)
        state.set_status(step_id, 'skipped')
        return 'skipped'

    # ── `when:` conditional ────────────────────────────────────────────────────
    when_expr = step.get('when')
    if when_expr is not None and not _eval_when(when_expr, ctx):
        info(f"Skipping '{step_id}' (when condition is false: {when_expr!r})")
        _step_event('SKIP', step_id)
        state.set_status(step_id, 'skipped')
        return 'skipped'

    step_name = step.get('name', '')
    name_suffix = f' — {step_name}' if step_name and step_name != step_id else ''
    info(f'Step: {step_id}{name_suffix}')
    _step_event('START', step_id)
    t_start = time.monotonic()

    # ── Fanout ────────────────────────────────────────────────────────────────
    if step.get('fanout') is not None:
        if state.print_plan:
            for child in step['fanout']:
                print(f'{step_id}.{child["id"]}: {render_template(child["run"], ctx)}')
            state.set_status(step_id, 'planned')
            _step_event('DONE', step_id)
            return 'ok'
        result = _execute_fanout(step, state)
        elapsed_ms = int((time.monotonic() - t_start) * 1000)
        _step_event('TIME', step_id, ms=elapsed_ms)
        return result

    # ── Regular step ──────────────────────────────────────────────────────────
    command = render_template(step['run'], ctx)
    outputs = {k: render_template(str(v), ctx) for k, v in (step.get('outputs') or {}).items()}

    # Resume / skip-if-exists
    existing_status = (
        state.resume_data.get('steps', {}).get(step_id, {}).get('status')
        if state.resume else None
    )
    should_skip = step.get('skip_if_exists') or existing_status == 'ok'
    if should_skip:
        cond = _check_requires(step['requires'], ctx, quiet=True) if step.get('requires') else _check_outputs(outputs, ctx)
        if cond:
            warn(f"Skipping '{step_id}' (already completed)")
            state.set_outputs(step_id, outputs)
            _step_event('SKIP', step_id)
            state.set_status(step_id, 'skipped')
            if state.resume:
                _record_resume(state, step_id, 'ok', outputs, skipped=True)
            return 'skipped'

    if state.print_plan:
        print(f'{step_id}: {command}')
        state.set_outputs(step_id, outputs)
        state.set_status(step_id, 'planned')
        _step_event('DONE', step_id)
        return 'ok'

    use_shell = bool(step.get('shell', False))
    optional = bool(step.get('optional', False))

    if not use_shell:
        _warn_missing_tool(command)

    if state.resume:
        _record_resume(state, step_id, 'running', outputs)

    ok = _run_command(
        command=command,
        cwd=_resolve_cwd(step, ctx, state.workspace),
        env=_make_env(step, ctx),
        timeout=_parse_timeout(step.get('timeout'), label=f"Step '{step_id}'"),
        retries=step.get('retries', 0),
        label=step_id,
        shell=use_shell,
    )
    state.set_outputs(step_id, outputs)

    if ok and step.get('requires') and not _check_requires(step['requires'], ctx):
        ok = False

    if not ok and optional:
        warn(f"Step '{step_id}' failed but is optional, continuing.")
        ok = True

    elapsed_ms = int((time.monotonic() - t_start) * 1000)
    status = 'ok' if ok else 'failed'
    state.set_status(step_id, status)
    _step_event('DONE' if ok else 'FAIL', step_id)
    _step_event('TIME', step_id, ms=elapsed_ms)

    if state.resume:
        _record_resume(state, step_id, status, outputs,
                       message=None if ok else f'Step failed: {step_id}')

    if not ok:
        warn(f"Step failed: '{step_id}'")

    return status


# ── Public entry point ────────────────────────────────────────────────────────

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
    if resume and out_dir is None:
        raise WorkflowError('--resume requires --out to specify the existing workspace to resume.')

    workflow = load_workflow(workflow_path)
    steps = topological_order(workflow['steps'])

    timestamp = time.strftime('%Y%m%d-%H%M%S')
    safe_target = re.sub(r'[^A-Za-z0-9._-]+', '_', target)
    workspace = (out_dir if out_dir else Path('runs') / safe_target / timestamp).resolve()
    workspace.mkdir(parents=True, exist_ok=True)

    resume_path = _resume_path(workspace)
    resume_data = _load_resume(resume_path) if resume else {'steps': {}}

    merged = dict(workflow.get('vars') or {})
    if var_overrides:
        merged.update(var_overrides)

    ctx: dict[str, Any] = {
        **merged,
        'vars': merged,
        'target': target,
        'workspace': str(workspace),
        'timestamp': timestamp,
        'steps': {},
        'status': {},
    }

    state = _RunState(
        ctx=ctx,
        workspace=workspace,
        resume=resume,
        resume_data=resume_data,
        resume_path=resume_path,
        print_plan=print_plan,
        continue_on_error=continue_on_error,
    )

    levels = _execution_levels(steps)
    t_run_start = time.monotonic()

    if print_plan:
        info('Plan only (no execution):')

    for level_steps in levels:
        n = len(level_steps)
        if n > 1 and not print_plan:
            ids = ', '.join(s['id'] for s in level_steps)
            info(f'Parallel ({n}): {ids}')
            with ThreadPoolExecutor(max_workers=n) as pool:
                fut_map = {pool.submit(_execute_step, s, state): s for s in level_steps}
                results: dict[str, str] = {}
                for fut in as_completed(fut_map):
                    s = fut_map[fut]
                    try:
                        results[s['id']] = fut.result()
                    except Exception as exc:
                        results[s['id']] = 'failed'
                        warn(f"Unexpected error in step '{s['id']}': {exc}")
            failed = [sid for sid, r in results.items() if r == 'failed']
            if failed and not continue_on_error:
                raise WorkflowError(f"Steps failed: {', '.join(failed)}")
        else:
            for step in level_steps:
                status = _execute_step(step, state)
                if status == 'failed' and not continue_on_error:
                    raise WorkflowError(f"Step failed: '{step['id']}'")

        # Check for pause request between execution levels (not mid-step).
        if not print_plan and _check_pause_flag(workspace):
            info('[PAUSED] Pause flag detected — checkpointing. Use Resume to continue.')
            sys.exit(PAUSE_EXIT_CODE)

    elapsed_total = time.monotonic() - t_run_start
    info(f'Workspace: {workspace}')
    info(f'Done in {elapsed_total:.1f}s.')

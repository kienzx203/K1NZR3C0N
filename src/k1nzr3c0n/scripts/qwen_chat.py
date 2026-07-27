#!/usr/bin/env python3
"""Qwen interactive chat REPL — runs inside a PTY spawned by the terminal WebSocket."""

from __future__ import annotations

import os
import sys
import readline  # noqa: F401 — enables arrow-key editing & history

BOLD   = '\033[1m'
DIM    = '\033[2m'
CYAN   = '\033[1;36m'
GREEN  = '\033[1;32m'
YELLOW = '\033[1;33m'
RED    = '\033[1;31m'
BLUE   = '\033[1;34m'
RESET  = '\033[0m'

BASE_URL = 'https://dashscope.aliyuncs.com/compatible-mode/v1'
DEFAULT_MODEL = os.environ.get('QWEN_MODEL', 'qwen-plus')

SYSTEM_PROMPT = (
    'You are a highly capable security research assistant embedded in k1nzr3c0n, '
    'a professional recon workflow runner. Help the user analyze targets, interpret '
    'tool outputs, suggest attack surface areas, explain vulnerabilities, and write '
    'effective recon queries. Be concise and technical. When asked for commands or '
    'payloads, provide them directly without excessive caveats.'
)

HELP_TEXT = f"""
{CYAN}{BOLD}Qwen AI Terminal — k1nzr3c0n{RESET}

{BOLD}Commands:{RESET}
  {GREEN}/help{RESET}              show this help
  {GREEN}/clear{RESET}             reset conversation history
  {GREEN}/model <name>{RESET}      switch model
  {GREEN}/models{RESET}            list available models
  {GREEN}/system <prompt>{RESET}   replace system prompt
  {GREEN}/history{RESET}           show message count
  {GREEN}/exit{RESET}  or  Ctrl+D  quit

{BOLD}Available models:{RESET}
  qwen-turbo          fast, cheap
  qwen-plus           {YELLOW}balanced (default){RESET}
  qwen-max            most capable
  qwen3-235b-a22b     latest flagship (slow)
  qwen3-32b           fast + smart
"""

BANNER = f"""
{CYAN}╔══════════════════════════════════════════════╗
║  k1nzr3c0n  ×  Qwen AI Terminal              ║
║  model : {DEFAULT_MODEL:<36}║
║  type  : /help for commands                  ║
╚══════════════════════════════════════════════╝{RESET}
"""


def stream_response(client, model: str, messages: list[dict]) -> str:
    stream = client.chat.completions.create(
        model=model,
        messages=messages,
        stream=True,
    )
    print()
    full = ''
    for chunk in stream:
        if not chunk.choices:
            continue
        token = chunk.choices[0].delta.content or ''
        print(token, end='', flush=True)
        full += token
    print(f'\n{DIM}───{RESET}')
    return full


def main() -> None:
    api_key = os.environ.get('DASHSCOPE_API_KEY', '').strip()
    if not api_key:
        print(f'\n{RED}[!] DASHSCOPE_API_KEY not set.{RESET}')
        print(f'{DIM}    Configure it in the Keys page, then reconnect.{RESET}\n')
        sys.exit(1)

    try:
        from openai import OpenAI
    except ImportError:
        print(f'{RED}[!] openai package not installed inside container.{RESET}\n')
        sys.exit(1)

    client = OpenAI(api_key=api_key, base_url=BASE_URL)
    model = DEFAULT_MODEL
    system_prompt = SYSTEM_PROMPT
    history: list[dict] = []

    print(BANNER)

    while True:
        try:
            prompt = input(f'{GREEN}qwen{RESET}{DIM}({model})>{RESET} ').strip()
        except (EOFError, KeyboardInterrupt):
            print(f'\n{DIM}bye.{RESET}\n')
            break

        if not prompt:
            continue

        # ── slash commands ────────────────────────────────────────────────────
        if prompt == '/exit':
            print(f'{DIM}bye.{RESET}\n')
            break

        if prompt == '/help':
            print(HELP_TEXT)
            continue

        if prompt == '/clear':
            history.clear()
            print(f'{DIM}[history cleared]{RESET}\n')
            continue

        if prompt == '/history':
            print(f'{DIM}[{len(history)} messages in context]{RESET}\n')
            continue

        if prompt == '/models':
            print(f'\n{DIM}  qwen-turbo  qwen-plus  qwen-max  qwen3-235b-a22b  qwen3-32b{RESET}\n')
            continue

        if prompt.startswith('/model '):
            model = prompt.split(' ', 1)[1].strip()
            print(f'{DIM}[model → {model}]{RESET}\n')
            continue

        if prompt.startswith('/system '):
            system_prompt = prompt.split(' ', 1)[1].strip()
            history.clear()
            print(f'{DIM}[system prompt updated, history cleared]{RESET}\n')
            continue

        # ── normal chat ───────────────────────────────────────────────────────
        history.append({'role': 'user', 'content': prompt})
        messages = [{'role': 'system', 'content': system_prompt}, *history]

        try:
            reply = stream_response(client, model, messages)
            history.append({'role': 'assistant', 'content': reply})
        except Exception as exc:
            print(f'\n{RED}[error] {exc}{RESET}\n')
            history.pop()


if __name__ == '__main__':
    main()

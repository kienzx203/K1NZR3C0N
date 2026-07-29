---
name: k1nzr3c0n-cmd-web3-audit
description: "Web3/blockchain security audit workflow. Scope: smart contracts (Solidity/EVM), DeFi protocols, NFT projects, bridges, governance systems. Static analysis with slither, symbolic execution with mythril, manual review checklist. NOT for cracking wallets or stealing funds — authorized audit only."
tags: [command, web3, blockchain, solidity, audit]
---

# /web3-audit — Web3 Security Audit

> **Authorized audits only**: CTF, audit competitions (Code4rena/Sherlock), or authorized bounty.
> **No unauthorized on-chain transactions.** Static analysis only unless explicitly in scope.

---

## Phase 0 — Audit Setup

```bash
CONTRACT_DIR="${CONTRACT_DIR:-./contracts}"
CHAIN="${CHAIN:-ethereum}"
AUDIT_DIR="/tmp/web3_audit_$(date +%Y%m%d_%H%M%S)"
mkdir -p "$AUDIT_DIR"

echo "=== WEB3 AUDIT SETUP ==="
echo "  Contract directory: ${CONTRACT_DIR}"
echo "  Chain: ${CHAIN}"
echo "  Audit output: ${AUDIT_DIR}"
echo ""
echo "Tools check:"
command -v slither &>/dev/null && echo "  [OK] slither" || echo "  [MISSING] pip install slither-analyzer"
command -v mythril &>/dev/null && echo "  [OK] mythril" || echo "  [MISSING] pip install mythril"
command -v solc &>/dev/null && echo "  [OK] solc" || echo "  [MISSING] install solc-select"
```

## Phase 1 — Slither Static Analysis

```bash
echo "=== Slither Static Analysis ==="
if command -v slither &>/dev/null; then
  slither "$CONTRACT_DIR" \
    --json "$AUDIT_DIR/slither.json" \
    --print human-summary \
    2>&1 | tee "$AUDIT_DIR/slither_output.txt"
  
  echo ""
  echo "High severity findings:"
  python3 -c "
import json
try:
  d = json.load(open('$AUDIT_DIR/slither.json'))
  for r in d.get('results', {}).get('detectors', []):
    if r.get('impact') in ['High', 'Critical']:
      print(f\"  [{r['impact']}] {r['check']}: {r['description'][:100]}\")
except: print('Parse error')
" 2>/dev/null
else
  echo "  slither not installed — run: pip install slither-analyzer"
fi
```

## Phase 2 — Manual Checklist

```bash
echo ""
echo "=== Manual Review Checklist ==="
cat << 'CHECKLIST'
Access Control:
  □ onlyOwner functions — who is owner? Can it change?
  □ tx.origin used? (phishing vulnerability)
  □ Initialize functions — can anyone call initialize()?
  □ Proxy + implementation — are permissions separate?

Reentrancy:
  □ External calls before state changes?
  □ .call{value:}() without reentrancy guard?
  □ ERC777 token hooks in transfer logic?

Integer Issues:
  □ SafeMath or Solidity 0.8+ overflow protection?
  □ Division before multiplication (precision loss)?
  □ Signed integer casting issues?

Flash Loan / Price Oracle:
  □ getReserves() in same block = flash loan manipulable?
  □ TWAP oracle used (not spot price)?
  □ Slippage protection (amountOutMin != 0)?

Upgradability:
  □ Storage slot collision in proxy pattern?
  □ Initialization on implementation contract?
  □ delegatecall to user-controlled address?

Token:
  □ Fee-on-transfer token compatibility?
  □ ERC20 return value checked?
  □ approve() race condition (use increaseAllowance)?

DeFi:
  □ Unchecked low-level call returns?
  □ msg.value in loop (stuck ETH)?
  □ Block timestamp used for randomness?
CHECKLIST
```

## Phase 3 — Mythril Symbolic Execution

```bash
echo ""
echo "=== Mythril Symbolic Execution (slow but thorough) ==="
if command -v mythril &>/dev/null; then
  for SOL_FILE in "$CONTRACT_DIR"/*.sol; do
    echo "  Analyzing: $SOL_FILE"
    myth analyze "$SOL_FILE" --solv 0.8.20 -t 3 \
      -o json 2>/dev/null >> "$AUDIT_DIR/mythril.json"
  done
  echo "  Output: $AUDIT_DIR/mythril.json"
else
  echo "  mythril not installed — run: pip install mythril"
  echo "  Alternative: https://remix.ethereum.org (MythX plugin)"
fi
```

## Phase 4 — DeFi-Specific Checks

```bash
echo ""
echo "=== DeFi Protocol Checks ==="
grep -rn 'transfer\|transferFrom\|safeTransfer' "$CONTRACT_DIR"/*.sol 2>/dev/null | \
  grep -v 'require\|bool\|returns' | head -10 | sed 's/^/  [ERC20-UNCHECKED?] /'

grep -rn 'block\.timestamp\|now\b' "$CONTRACT_DIR"/*.sol 2>/dev/null | \
  head -10 | sed 's/^/  [TIMESTAMP?] /'

grep -rn '\.call{' "$CONTRACT_DIR"/*.sol 2>/dev/null | \
  grep -v 'require(' | head -10 | sed 's/^/  [UNCHECKED-CALL?] /'

grep -rn 'delegatecall' "$CONTRACT_DIR"/*.sol 2>/dev/null | \
  head -10 | sed 's/^/  [DELEGATECALL] /'

echo ""
echo "=== Audit Complete ==="
echo "  Slither: ${AUDIT_DIR}/slither.json"
echo "  Mythril: ${AUDIT_DIR}/mythril.json"
echo "  Manual checklist: review above items"
echo ""
echo "  Submit to Code4rena: https://code4rena.com"
echo "  Submit to Sherlock: https://audits.sherlock.xyz"
echo "  Submit to Immunefi: https://immunefi.com"
```

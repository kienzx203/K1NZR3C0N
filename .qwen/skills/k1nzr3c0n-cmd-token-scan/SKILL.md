---
name: k1nzr3c0n-cmd-token-scan
description: "Smart contract security audit. 8-class grep patterns for Solidity/EVM contracts: hidden mint, honeypot sell restriction, fee manipulation, LP drain, bonding curve manipulation, authority check bypass, fake renounce (still has owner), sandwich amplification. For Web3 bug bounty programs. Read-only analysis — no on-chain transactions."
tags: [command, web3, solidity, smart-contract, audit]
---

# /token-scan — Smart Contract Audit

> Usage: `/token-scan --contract=ContractAddress` or point at .sol files
> **Read-only**: static analysis only. No on-chain transactions executed.
> **Verify everything** against actual deployed bytecode on Etherscan/BSCScan.

---

## Setup

```bash
CONTRACT="${CONTRACT:-0x...}"
CHAIN="${CHAIN:-ethereum}"
SCAN_DIR="/tmp/token_scan_${CONTRACT:0:10}"
mkdir -p "$SCAN_DIR"

echo "=== SMART CONTRACT AUDIT ==="
echo "  Contract: ${CONTRACT}"
echo "  Chain:    ${CHAIN}"
echo ""
echo "Fetch source from Etherscan (if verified):"
echo "  https://etherscan.io/address/${CONTRACT}#code"
echo "  Save .sol files to: ${SCAN_DIR}/"
```

## Class 1 — Hidden Mint

```bash
echo "=== Class 1: Hidden Mint ==="
grep -rn 'mint\|_mint\|_totalSupply +=' "$SCAN_DIR"/*.sol 2>/dev/null | \
  grep -v 'constructor\|public\|external' | sed 's/^/  [HIDDEN-MINT?] /'

echo ""
echo "Red flags:"
echo "  - mint() not gated by onlyOwner/AccessControl"
echo "  - _totalSupply can be increased post-deployment"
echo "  - Hidden mint via airdrop/staking reward with no cap"
```

## Class 2 — Honeypot Sell Restriction

```bash
echo "=== Class 2: Honeypot Sell Restriction ==="
grep -rn 'transfer\|_transfer\|require.*sell\|blacklist\|whitelist\|trading\|canSell\|_allowed' \
  "$SCAN_DIR"/*.sol 2>/dev/null | sed 's/^/  /'

echo ""
echo "Red flags:"
echo "  - transfer() has require(from != blacklist[from])"
echo "  - Only owner can add addresses to whitelist (can block all sells)"
echo "  - isTrading flag that owner can toggle off"
echo "  - cooldown between sells with admin-adjustable duration"
```

## Class 3 — Fee Manipulation

```bash
echo "=== Class 3: Fee Manipulation ==="
grep -rn 'fee\|tax\|_fee\|buyFee\|sellFee\|maxFee\|setFee\|updateFee' \
  "$SCAN_DIR"/*.sol 2>/dev/null | sed 's/^/  /'

echo ""
echo "Red flags:"
echo "  - Owner can set fee to 100% (no upper cap)"
echo "  - Different buy/sell fees (sell fee set to drain on exit)"
echo "  - Fee recipient is owner address"
```

## Class 4 — LP Drain

```bash
echo "=== Class 4: Liquidity Pool Drain ==="
grep -rn 'removeLiquidity\|withdrawLP\|rescueToken\|recoverToken\|emergencyWithdraw\|_burnLP' \
  "$SCAN_DIR"/*.sol 2>/dev/null | sed 's/^/  [LP-DRAIN?] /'

echo ""
echo "Red flags:"
echo "  - Owner can call removeLiquidity() directly"
echo "  - emergencyWithdraw() with no timelock"
echo "  - rescueToken() that includes LP tokens"
```

## Class 5 — Bonding Curve Manipulation

```bash
echo "=== Class 5: Bonding Curve / Price Oracle ==="
grep -rn 'getPrice\|_price\|reserve\|getReserve\|spot\|oracle\|TWAP\|lastPrice' \
  "$SCAN_DIR"/*.sol 2>/dev/null | sed 's/^/  /'

echo ""
echo "Red flags:"
echo "  - Price from getReserves() in same block = flash loan vulnerable"
echo "  - No TWAP oracle (uses spot price)"
echo "  - Price calculation divides by small number (precision loss)"
```

## Class 6 — Authority Check Bypass

```bash
echo "=== Class 6: Authority Check Bypass ==="
grep -rn 'onlyOwner\|require.*owner\|msg.sender.*owner\|_owner\|Ownable' \
  "$SCAN_DIR"/*.sol 2>/dev/null | head -20 | sed 's/^/  /'

echo ""
echo "Red flags:"
echo "  - tx.origin used instead of msg.sender (phishing bypass)"
echo "  - Owner check on wrong variable (_owner vs owner)"
echo "  - Constructor sets owner to msg.sender but initialize() can re-run"
```

## Class 7 — Fake Renounce

```bash
echo "=== Class 7: Fake Ownership Renounce ==="
grep -rn 'renounceOwnership\|transferOwnership\|owner.*address(0)' \
  "$SCAN_DIR"/*.sol 2>/dev/null | sed 's/^/  /'

echo ""
echo "Red flags:"
echo "  - renounceOwnership() transfers to hidden address, not address(0)"
echo "  - _owner is private but can be changed via abi-encoded call"
echo "  - Proxy pattern: renounce on proxy but implementation still has owner"
```

## Class 8 — Sandwich Amplification

```bash
echo "=== Class 8: Sandwich Amplification ==="
grep -rn 'swap\|amountOutMin\|amountOut\|slippage\|deadline\|block.timestamp' \
  "$SCAN_DIR"/*.sol 2>/dev/null | sed 's/^/  /'

echo ""
echo "Red flags:"
echo "  - amountOutMin = 0 in contract-initiated swaps (no slippage protection)"
echo "  - deadline = block.timestamp (transaction can be held by miner)"
echo "  - Large single swap without TWAP protection"
```

## Summary

```bash
echo ""
echo "=== Audit Summary ==="
echo "  Review all [?] findings manually against deployed bytecode"
echo "  Verify on: https://etherscan.io/address/${CONTRACT}#code"
echo "  Cross-reference: https://code4rena.com (similar contracts audited)"
echo ""
echo "  Red: Hidden mint, LP drain, honeypot sell restriction → immediate dump risk"
echo "  Orange: Fee manipulation, authority bypass → slow rug potential"
echo "  Yellow: Sandwich, oracle manipulation → DeFi interaction risk"
```

# ai-hallucination-wall 🧠🧱

[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-v1.0.0-orange?logo=githubactions)](https://github.com/OrderStream/ai-hallucination-wall)

[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![CI](https://img.shields.io/badge/CI-Passing-brightgreen.svg)]()
[![OrderStream Polar](https://img.shields.io/badge/Polar-OrderStream-blue.svg)](https://polar.sh/orderstream)
[![Stellar XLM/USDC](https://img.shields.io/badge/Stellar-USDC%2FXLM-black.svg)](#direct-web3-wallet-monetization)
[![Base USDC](https://img.shields.io/badge/Base-USDC-0052FF.svg)](#direct-web3-wallet-monetization)

Security guardrail that inspects autonomous AI coding agent tool invocations, blocking hallucinated or typosquatted npm/PyPI dependencies.

---

## 💥 The Friction & Dollar Cost
Autonomous AI coding agents (Claude Code, Cursor, Copilot, SWE-bench bots) frequently invent imaginary packages or make typos when calling shell tools:
- The AI runs `npm install express-cors-fix` or `pip install reqeusts`.
- Attackers register these known hallucination patterns on public registries with malicious payloads that exfiltrate `.env` secrets, AWS credentials, and crypto private keys.
- **Slopsquatting** has become the fastest-growing supply chain attack vector against AI developers.

**ai-hallucination-wall** acts as an active firewall:
1. Intercepts CLI installation invocations before execution.
2. Compares against vetted registry databases and calculates Levenshtein distance against high-profile targets.
3. Blocks slopsquats, typo-squats, and hallucinated suffix packages instantly.

---

## 🚀 Quick Start

### Installation
```bash
pip install ai-hallucination-wall
```

### CLI Usage
```bash
# Intercept an agent command before running it
ai-hallucination-wall check-command --cmd "npm install expres"

# Scan manifest files in PRs
ai-hallucination-wall scan-manifest --file requirements.txt

# Inspect a package name directly
ai-hallucination-wall check-package --name "requests-official"

# Check license & zero-fee wallet payment details
ai-hallucination-wall license
```

---

## 🤖 GitHub Action Integration

```yaml
- name: AI Hallucination Wall
  uses: OrderStream/ai-hallucination-wall@v1
  with:
    manifest: "requirements.txt"
```

---

---

## 💳 Enterprise Pricing Matrix & Licensing

| Tier | Price | Repositories | Core Capabilities |
| :--- | :--- | :--- | :--- |
| **Community Free** | **** | Unlimited | Standalone CLI runner and single-repo GitHub Action |
| **Starter Suite** | ** / mo** | Up to 10 Repos | Automated CI PR gates, 500 CI runs/mo, standard email support |
| **Team Platform** | **,499 / mo** | Up to 50 Repos | Full 10-tool OrderStream suite, flaky test quarantine deterministic replay, zero-downtime shadow DB migration guard, 24/7 telemetry alarms |
| **Enterprise Platform** | **,999 / mo** | Unlimited | Multi-repo speculative merge engine, zero-downtime migration orchestrator, WASM sandbox gate, dedicated 24/7 cloud keeper, custom SLA |
| **M&A IP & Security Audit** | **,000 one-time** | Whole Organization | Comprehensive copyleft AST fuzzy fingerprint audit, snippet license sheriff certification, formal invariant verification, and executive forensic IP Cleanliness Certificate |

## 💰 Direct Web3 Wallet Monetization & Polar Integration

Support this project or purchase enterprise zero-day threat intelligence with **0 platform fees**:

- **Polar Subscription & Sponsorship:** [https://polar.sh/orderstream](https://polar.sh/orderstream)
- **Stellar Network (Native XLM / USDC):**
  - Public Key: `GABFQIK63R2NETJM7T673EAMZN4RJLLGP3OFUEJU5ZVTGWUKULZJNL6`
  - Memo (Required): `400566831`
- **EVM (Base / Arbitrum / Ethereum USDT & USDC):**
  - Address: `0x5de2b62434754bfd39ef350a3a867ed3eced5074`

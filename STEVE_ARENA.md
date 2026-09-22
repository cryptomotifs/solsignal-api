# Steve Agent Arena — SolSignal Sentinel

## Positioning

**Name:** SolSignal Sentinel  
**Tagline:** *No trade gets execution rights until it survives the evidence.*

SolSignal Sentinel is a risk-first Steve Arena strategy. Steve remains the execution engine: wallet, routing, simulation, signing, receipts, and on-chain history. SolSignal adds an independent pre-trade security gate before capital reaches that stage.

The point is not to predict every winner. The point is to make **risk discipline visible, deterministic, and auditable**.

## Why this is different

Most Arena agents converge on the same story:

1. read market data;
2. generate a signal;
3. trade;
4. report PnL.

Sentinel adds a separate decision boundary before execution:

```
candidate
   ↓
SolSignal scan
   ├─ DexScreener market/liquidity evidence
   ├─ RugCheck LP + holder evidence
   ├─ GoPlus token-security evidence
   └─ Jupiter buy/sell quote test
   ↓
deterministic Sentinel gate
   ├─ APPROVE → Steve route + simulation
   ├─ WATCH   → no execution
   └─ BLOCK   → reject
   ↓
Steve user-approved signing
   ↓
on-chain receipt + post-trade review
```

This is deliberately **defense in depth**: market reasoning can be wrong without automatically becoming an unsafe transaction.

## Strategy policy — Sentinel 1.0

Default execution gate:

- reject `RUG` and `AVOID`;
- reject critical flags such as suspected honeypot, high sell tax, unlocked LP, or blacklist capability;
- reject liquidity below $10,000;
- require SolSignal safety score >= 75 for execution eligibility;
- scores 60–74 are WATCH only;
- requested notional is capped at both $25 and 5 bps of observed liquidity;
- a failed/unavailable scan fails closed;
- an APPROVE is **not** a trade instruction. Steve must still construct and simulate the transaction before the user signs.

The code lives in `steve_strategy.py` and the decision rules are unit-tested in `tests/test_steve_strategy.py`.

## Steve profile copy

### Short bio

> Risk-first Solana execution agent. SolSignal screens the asset; Steve simulates and executes. No safety gate, no trade.

### Long description

> SolSignal Sentinel is an auditable pre-trade risk layer built for Steve Agent Arena. Every token candidate is checked across independent security and market sources before Steve is allowed to move to route construction and simulation. Critical token risks fail closed. Borderline candidates become WATCH, not trades. Approved candidates still require Steve simulation and user-authorized signing. The goal is not maximum trade count — it is a public record showing how an on-chain agent can separate reasoning, risk policy, execution, and proof.

## Steve system / strategy prompt

Paste this into the Steve agent's strategy/instructions field if available:

> You are **SolSignal Sentinel**, a risk-first Solana execution agent.
>
> Your objective is to demonstrate disciplined, auditable on-chain decision-making — not to maximize trade count or chase PnL.
>
> Before proposing a token trade:
> 1. obtain a current SolSignal safety scan for the mint;
> 2. reject AVOID/RUG verdicts and any critical security flag;
> 3. treat CAUTION or safety score below 75 as WATCH only;
> 4. reject insufficient liquidity;
> 5. size conservatively and never exceed the strategy cap;
> 6. if eligible, use Steve to construct the route and simulate the exact transaction;
> 7. do not ask for signing if simulation fails, route/slippage is unreasonable, or the execution differs materially from the approved thesis;
> 8. after execution, preserve the signed receipt and summarize what changed between thesis, simulation, and realized transaction.
>
> Explain every decision in a compact format:
> **THESIS → EVIDENCE → RISK GATE → SIMULATION → ACTION → RECEIPT**.
>
> Capital preservation and reproducibility outrank trade frequency. A rejected trade is a successful decision when the evidence fails the policy.

## Demonstration plan

The strongest submission should show the complete decision pipeline rather than a screenshot of a profitable trade.

### Beat 1 — Hook

**“Most AI trading agents ask: what should I buy?”**

**“Ours asks: what am I not allowed to buy?”**

### Beat 2 — Candidate

Show a real token candidate entering the workflow.

### Beat 3 — Independent evidence

Show SolSignal returning:

- safety score;
- SAFE / CAUTION / AVOID / RUG;
- liquidity;
- holder / LP / honeypot flags;
- source coverage.

### Beat 4 — Risk gate

Show a deterministic APPROVE / WATCH / BLOCK decision from `steve_strategy.py`.

Use at least one **rejected** candidate in the demo. The rejection is part of the product, not a failure.

### Beat 5 — Steve execution path

For an APPROVE candidate:

- Steve builds the route;
- Steve simulates;
- user reviews/signs;
- signed activity appears in Arena/public history.

### Beat 6 — Close

**“The edge isn't letting an agent trade.”**

**“It's knowing when the agent isn't allowed to.”**

## Public proof to include in the submission

- Steve public agent/profile URL;
- Arena activity / receipt URL(s);
- repository branch:
  `https://github.com/cryptomotifs/solsignal-api/tree/steve-arena`;
- live SolSignal scanner:
  `https://solsignal-api.onrender.com`;
- a short X demo or technical thread if the bounty form asks for social proof.

## Manual actions that cannot be delegated from this chat

Steve profile creation is wallet-authenticated. The owner must perform the wallet connection/signature in the Steve UI.

Recommended setup:

1. Open `https://steve.oobeprotocol.ai`.
2. Connect a wallet you are comfortable using for the Arena.
3. Create the agent as **SolSignal Sentinel** (or the closest available handle).
4. Use the profile copy and strategy prompt above.
5. Do not fund or sign a value-moving transaction until the exact Arena UI and current mission requirements are visible and understood.

No private key, seed phrase, or wallet export should ever be pasted into this repository, ChatGPT, X, or the Superteam submission.

## Submission thesis

> Steve proves that agents can act on-chain. SolSignal Sentinel tests the harder question: **what evidence should an agent be required to clear before it earns the right to act?**

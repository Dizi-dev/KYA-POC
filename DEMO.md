# KYA Gateway: 3-minute demo

For a non-technical co-founder. You need a terminal in the repo folder with Python 3.11+ and
Node 18+. The first run of `scripts/verify.sh` sets up everything (about a minute).

## 0. Before the call (once)

```bash
scripts/verify.sh
```

What appears: a table of steps ending in `Overall: PASS`.
Why it matters: one command re-proves everything below. The results sit in `evidence/`.

## 1. The demo shop under attack (60 s)

```bash
.venv/bin/python -m demo.run_demo
```

What appears (from `evidence/demo.log`):

```
 1. Acme agent browses a product (signed)          200  outcome=verified   decision=allow
 2. Acme agent checks out (TAP agent-payer-auth)   200  outcome=verified   decision=allow
 3. Acme agent pulls the price API (signed)        402  outcome=verified   decision=charge
 4. Attacker replays request 1 headers             403  outcome=invalid    decision=block
 5. Attacker forges Acme's identity                403  outcome=invalid    decision=block
 6. Scraper sends 'GPTBot' User-Agent, no signature 403  outcome=unsigned   decision=block
 7. Unknown agent, directory offline (try 3)       429  outcome=unverified decision=rate_limit
 8. Human with a normal browser                    200  outcome=unsigned   decision=allow
 9. Acme rotates: request signed with NEW key      200  outcome=verified   decision=allow
 9. Acme rotates: OLD key still published          200  outcome=verified   decision=allow
 9. OLD key after Acme removed it (cache expired)  429  outcome=unverified decision=rate_limit
```

What to say, line by line:
- **1 to 3:** a real AI shopping agent proves who it is with a cryptographic signature. The
  shop lets it browse and check out, and charges it for the price API (402 = "pay first").
- **4 and 5:** an attacker copies a real request, or pretends to be Acme. Both are blocked,
  because a signature can't be reused or faked.
- **6:** a scraper that only *claims* to be GPTBot in its User-Agent text is blocked. Today
  most sites can't tell the difference.
- **7:** an agent we can't check yet is allowed a little traffic, then slowed down.
- **8:** normal people are never affected.
- **9:** Acme replaces its key. The new key works straight away, and the old one stops
  working once Acme withdraws it. Nobody at the shop had to do anything.

## 2. The tamper-detection moment (30 s)

Same output, bottom lines:

```
Audit chain: 13 entries, chain intact
After editing entry 5 in the database: chain broken at entry 5
```

What to say: every decision is logged, and each log entry is chained to the one before it.
The demo then edits entry 5 directly in the database, to hide the forged request by changing
"block" to "allow". The gateway immediately reports exactly which entry was changed.
Why it matters: in a dispute ("your site charged my agent", "your agent scraped us"), the log
is evidence that nobody quietly rewrote it.

## 3. The dashboard (30 s)

```bash
open evidence/dashboard_snapshot.html
```

What appears: counts by outcome, decision and operator, plus one row per request with its
hash. The chain status shows in red, because the demo tampered with it.
Why it matters: this is what a store owner pays for. Anyone can verify signatures for free;
the policy, the log and this view are the product.

## 4. It works against the real internet (45 s)

```bash
.venv/bin/python -m examples.walkthrough
```

This runs an ordinary shop app in **production mode**. The gateway fetches ChatGPT's and
Google's real public keys over the internet. From `evidence/walkthrough.log`:

```
  Attacker signs as ChatGPT (real ChatGPT keyid, wrong key)  403  invalid    block      signature does not match
  Unknown key pointing at chatgpt.com directory (try 3)      429  unverified rate_limit keyid not published in the agent's directory
  Attacker signs as Google-Agent (real Google keyid)         403  invalid    block      signature does not match
```

What to say: someone impersonating ChatGPT or Google is caught using their real published
keys.
Why it matters: 87 of the 96 agent operators registered with Cloudflare publish keys that
this gateway loads today, including Google, AWS, Meta and DuckDuckGo
(`evidence/signed_agents_survey.log`).

**Be honest if asked:** we have not yet seen a *genuine* ChatGPT or Google request pass through
it. That needs the shop on a public web address and a real agent visiting it (next step in
REPORT.md).

---
No asciinema recording: asciinema is not installed on this machine, so `evidence/demo.log`,
written by `verify.sh`, is the recording.

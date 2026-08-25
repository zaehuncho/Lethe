# Lethe Bounty Challenge

A **money-bounty** challenge ("recover the flag, win $X") built to be *actually*
unwinnable — unlike the red-team crackme (`../cipher/gen_check_vm.py`), whose
strength came from a toy FNV gate and obscurity.

## Threat model — assume the client is fully reversed

Two capable analysts (and two AIs) devirtualized the crackme's VM and recovered
both formulas in ~1–2 hours. **Assume any attacker knows the entire algorithm,
the salt, the nonce and the ciphertext.** So the security rests only on what
reversing cannot hand them:

1. a **high-entropy password** they must supply, and
2. a **slow, memory-hard KDF** (Argon2id) that makes each guess expensive,

with the flag sealed under **AES-256-GCM** so a wrong password fails
*authentication* — there is no decrypt-to-garbage oracle and no partial leak.

> **Frame the bounty as "recover the flag," never "unpack the binary."**
> Unpacking is expected and cheap; the flag is the wall.

## Scheme (`lethe-bounty-v1`)

```
key = Argon2id(password, salt, t=4, m=256 MiB, p=1) → 32 bytes
ciphertext = AES-256-GCM(key, nonce, flag, aad="lethe-bounty-v1")
```

The public challenge (`challenge.json`) contains **only** `salt`, `nonce`,
`ciphertext` and the KDF parameters — never the password, flag or key. Crypto is
**not hand-rolled**: Argon2id comes from `argon2-cffi` (the reference C core) and
AES-GCM from `cryptography`. A stdlib `scrypt` fallback is used automatically if
`argon2-cffi` is not installed.

## Files

| File | Role |
|------|------|
| `lethe_bounty.py` | core: `generate()`, `attempt()`, `derive_key()`, `Challenge` |
| `gen_bounty.py`   | build `challenge.json` from `LETHE_CRACKME_PASSWORD/FLAG` (env) |
| `solve_bounty.py` | the reference check a solver runs against a guess |
| `audit_bounty.py` | **prove the artifact leaks nothing** — run before publishing |

## Usage

```powershell
# secrets come from the environment, never the repo
$env:LETHE_CRACKME_PASSWORD='<the real password>'
$env:LETHE_CRACKME_FLAG='NEXUS{...}'

python bounty/gen_bounty.py --out challenge.json         # seal the flag
python bounty/audit_bounty.py challenge.json             # MUST print PASS
python bounty/solve_bounty.py challenge.json --password guess   # what solvers run
```

`gen_bounty.py` self-checks (real password recovers the flag; a wrong one fails)
before it writes anything. `audit_bounty.py` is the gate: it exits non-zero unless
the password, flag and derived key are absent from every shipped artifact and a
battery of wrong guesses (including feeding the flag as the password) reveal
nothing. **Do not stake money until the audit prints PASS.**

## Shipping a native binary (optional obfuscation layer)

`challenge.json` + `solve_bounty.py` is already a complete, safe challenge. To
ship a self-contained `.exe` instead:

1. Write a small native check that embeds only `salt`/`nonce`/`ciphertext`, reads
   a password, runs **libargon2** (reference, public-domain) + **BCrypt AES-GCM**
   (`BCryptEncrypt`/`Decrypt`, `BCRYPT_CHAIN_MODE_GCM` — OS-provided, vetted), and
   prints the flag on tag-verify. **Do not hand-roll Argon2 or AES-GCM.**
2. Strip symbols; confirm no PDB ships.
3. Pack it with Lethe (`python ../lethe.py check.exe check.packed.exe`) for the
   cost-multiplier layer.
4. Re-run `audit_bounty.py challenge.json --binary check.packed.exe` — the binary
   must contain none of the secret bytes.

The packing is *obfuscation*, not the wall. Even a fully-unpacked binary yields
only `salt`/`nonce`/`ciphertext` — useless without the password.

## Bounty rules (template — tighten before publishing)

- **Goal:** produce the exact flag string sealed in `challenge.json`. Offline;
  this exact artifact only.
- **Not in scope:** attacking our infrastructure, build servers, or staff; social
  engineering; side channels outside the published artifact.
- **Payout:** single winner, first verified flag, one payment; time-boxed.
- **Honest budget:** treat the prize as a *small real risk*, not zero — these
  bounties are lost to implementation bugs, not broken math. The audit is what
  keeps the math side sound; keep the password long, random and non-dictionary.

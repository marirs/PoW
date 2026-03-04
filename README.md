# PoW

Multi-round, timing-validated, binding-aware Proof-of-Work challenge system for web applications.

## Why

Traditional single-round SHA-256 PoW (like mCaptcha, Anubis, etc.) is trivially defeated by native solvers. Tools like [pow-buster](https://github.com/nicholasgasior/pow-buster) achieve **800–1000x speedup** over browser JavaScript using SIMD (AVX-512/SHA-NI), hotstarting, and data-parallel search — making any "fair" difficulty setting impossible.

This crate implements the defenses recommended by adversarial PoW research to neutralize those advantages.

## Defense Layers

### 1. Multi-round challenge-response

The server issues **N sequential mini-challenges** (default: 3). Each round's input is derived from the previous round's solution hash. The client must HTTP round-trip each answer to get the next challenge.

**Why it works:** SIMD and GPU parallelism become useless — you can't batch rounds because you don't know the next input until the server responds. Network latency (~50–200ms) becomes the dominant cost, equalizing browsers and native solvers.

### 2. Timing validation

The server records when each round was issued. If a solution arrives faster than `min_round_ms` (default: 50ms), it's rejected as a native solver.

**Why it works:** Even the fastest native solver can't beat physics — the round-trip latency floor applies to everyone. Solutions arriving in <50ms are physically impossible from a browser and indicate automated solving.

### 3. Challenge binding

Each challenge chain is bound to `HMAC-SHA256(server_secret, IP | User-Agent | session_nonce)`. The binding is embedded in every round prefix.

**Why it works:** A challenge solved on machine A can't be submitted from machine B. Farming challenges to a separate solver cluster requires matching the exact IP and User-Agent, which significantly raises the attack cost.

### 4. Hardened SHA-256

The challenge prefix is deliberately >55 bytes, forcing SHA-256 into **double-block mode** (two compression rounds instead of one). Nonces must be lowercase hex strings.

**Why it works:**
- Single-block hotstarting (pre-computing the SHA-256 internal state up to the nonce) only works when `prefix + nonce ≤ 55 bytes`. Our prefix is ~99 bytes, so the attacker must always run two compression rounds.
- Hex-only nonces prevent integer-encoding tricks that keep messages artificially short.

## Usage

```rust
use pow::{PowConfig, PowStore, RoundResult};

// Server setup
let config = PowConfig {
    rounds: 3,          // 3 sequential challenges
    difficulty: 16,     // 16 leading zero bits per round (~65k hashes)
    min_round_ms: 50,   // reject solutions faster than 50ms
    max_chain_secs: 120,
    max_round_secs: 60,
};
let store = PowStore::new(config, b"your-server-secret".to_vec());

// When client loads the login page:
let chain = store.create_chain("client_ip", "user_agent");
// Send to client: chain.chain_id, chain.current_prefix, chain.difficulty, chain.total_rounds

// Client solves round 0 and POSTs the nonce:
match store.submit_round(&chain.chain_id, "solved_nonce_hex") {
    RoundResult::NextRound { prefix, difficulty, round, total_rounds } => {
        // Send next challenge to client
    }
    RoundResult::Complete => {
        // All rounds passed — allow form submission
    }
    RoundResult::Rejected { reason } => {
        // Failed — reason is one of: unknown_chain, chain_expired,
        // round_expired, too_fast, invalid_proof
    }
}

// Periodic cleanup (call every ~30s)
store.cleanup_expired();
```

## Browser Integration

The crate includes an embedded JavaScript solver (`pow::solver_js()`) that:
- Solves each round using `crypto.subtle.digest("SHA-256", ...)`
- POSTs each solution to `/pow/submit` and receives the next round
- Shows progress (`Verifying (1/3)… (2/3)… (3/3)…`)
- Sets a hidden form field to `"complete"` when all rounds pass

## Configuration

| Parameter | Default | Description |
|-----------|---------|-------------|
| `rounds` | 3 | Number of sequential challenges |
| `difficulty` | 16 | Leading zero bits required per round |
| `min_round_ms` | 50 | Minimum acceptable solve time per round (ms) |
| `max_chain_secs` | 120 | Maximum time for the entire chain (s) |
| `max_round_secs` | 60 | Maximum time for a single round (s) |

## Environment Variables

| Variable | Required | Description |
|----------|----------|-------------|
| `POW_SECRET` | No | Server secret for HMAC binding. Random per-boot if unset. Set this to persist challenge validity across restarts. |

## License

MIT OR Apache-2.0

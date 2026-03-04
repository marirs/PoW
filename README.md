# PoW

[![CI](https://github.com/torq-x/PoW/actions/workflows/ci.yml/badge.svg)](https://github.com/torq-x/PoW/actions/workflows/ci.yml)
[![License: MIT/Apache-2.0](https://img.shields.io/badge/license-MIT%2FApache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-2024_edition-orange.svg)](https://www.rust-lang.org)

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

There are two ways to integrate the client-side solver: use the **embedded JS** from Rust, or write **your own HTML/JS**.

---

### Option A: Using `solver_js()` from Rust

The crate ships a self-contained JavaScript solver accessible via `pow::solver_js()`. This is the quickest path — you render the HTML form with hidden fields, inject the JS, and you're done.

**Server-side** — inject the JS and chain data into your template:

With Rocket + Tera:

```rust
use pow::{PowStore, solver_js};

#[get("/login")]
fn login_page(store: &State<Arc<PowStore>>, real_ip: RealIp, ua: UserAgent) -> Template {
    let chain = store.create_chain(&real_ip.0, &ua.0);
    Template::render("login", serde_json::json!({
        "pow_chain_id":    chain.chain_id,
        "pow_prefix":      chain.current_prefix,
        "pow_difficulty":   chain.difficulty,
        "pow_total_rounds": chain.total_rounds,
        "pow_solver_js":   solver_js(),
    }))
}
```

With Axum + Askama/Maud/etc:

```rust
use pow::{PowStore, solver_js};

async fn login_page(State(store): State<Arc<PowStore>>, ip: ConnectInfo<SocketAddr>, headers: HeaderMap) -> Html<String> {
    let ua = headers.get("user-agent").and_then(|v| v.to_str().ok()).unwrap_or("");
    let chain = store.create_chain(&ip.0.ip().to_string(), ua);
    // pass chain.chain_id, chain.current_prefix, chain.difficulty,
    // chain.total_rounds, and solver_js() to your template
}
```

**HTML template** — add hidden fields and render the solver JS:

```html
<form method="post" action="/login" id="login-form">
  <!-- your form fields here -->

  <input type="hidden" name="pow_chain_id" id="pow_chain_id" value="{{ pow_chain_id }}"/>
  <input type="hidden" name="pow_nonce"    id="pow_nonce"    value=""/>
  <input type="hidden" id="pow_prefix"       value="{{ pow_prefix }}"/>
  <input type="hidden" id="pow_difficulty"   value="{{ pow_difficulty }}"/>
  <input type="hidden" id="pow_total_rounds" value="{{ pow_total_rounds }}"/>

  <button type="submit" id="login-btn" disabled>
    <span id="pow-status">Verifying…</span>
    <span id="pow-ready" style="display:none">Submit</span>
  </button>
</form>
<style>@keyframes spin { to { transform:rotate(360deg) } }</style>

<script>{{ pow_solver_js | safe }}</script>
```

The embedded solver expects these element IDs: `pow_chain_id`, `pow_nonce`, `pow_prefix`, `pow_difficulty`, `pow_total_rounds`, `pow-status`, `pow-ready`, and `login-btn`. It handles solving all rounds, POSTing to `/pow/submit`, and enabling the button when done.

That's it — no custom JavaScript needed.

---

### Option B: Writing Your Own HTML/JS

If you want full control over the DOM, styling, element IDs, or submit endpoint, write your own solver. Here's a complete reference implementation.

**HTML form:**

```html
<form method="post" action="/login" id="login-form">
  <!-- your form fields here -->

  <input type="hidden" name="pow_chain_id" id="pow_chain_id" value="{{ chain_id }}"/>
  <input type="hidden" name="pow_nonce"    id="pow_nonce"    value=""/>
  <input type="hidden" id="pow_prefix"       value="{{ prefix }}"/>
  <input type="hidden" id="pow_difficulty"   value="{{ difficulty }}"/>
  <input type="hidden" id="pow_total_rounds" value="{{ total_rounds }}"/>

  <button type="submit" id="submit-btn" disabled>
    <span id="pow-status">Verifying…</span>
    <span id="pow-ready" style="display:none">Submit</span>
  </button>
</form>
```

Your server template injects `chain_id`, `prefix`, `difficulty`, and `total_rounds` from the `ChainState` returned by `store.create_chain(ip, ua)`.

**JavaScript solver:**

```html
<script>
(function() {
  var chainId    = document.getElementById('pow_chain_id').value;
  var prefix     = document.getElementById('pow_prefix').value;
  var difficulty  = parseInt(document.getElementById('pow_difficulty').value, 10);
  var totalRounds = parseInt(document.getElementById('pow_total_rounds').value, 10);
  var currentRound = 0;

  // Graceful fallback if crypto.subtle is unavailable (HTTP without TLS)
  if (!chainId || !prefix || difficulty <= 0 || typeof crypto === 'undefined' || !crypto.subtle) {
    document.getElementById('submit-btn').disabled = false;
    document.getElementById('pow-status').style.display = 'none';
    document.getElementById('pow-ready').style.display = '';
    return;
  }

  function hexFromBuf(buf) {
    var a = new Uint8Array(buf), h = '';
    for (var i = 0; i < a.length; i++) h += ('0' + a[i].toString(16)).slice(-2);
    return h;
  }

  function leadingZeroBits(h) {
    var b = 0;
    for (var i = 0; i < h.length; i++) {
      var v = parseInt(h[i], 16);
      if (v === 0) { b += 4; }
      else { if (v < 2) b += 3; else if (v < 4) b += 2; else if (v < 8) b += 1; break; }
    }
    return b;
  }

  function updateStatus() {
    document.getElementById('pow-status').textContent =
      'Verifying (' + (currentRound + 1) + '/' + totalRounds + ')…';
  }

  // Solve one round: brute-force a 16-char hex nonce where
  // SHA-256(prefix + nonce) has >= difficulty leading zero bits
  function solveRound(pfx, diff, onFound) {
    var found = false, nonce = 0;
    function batch() {
      if (found) return;
      var size = 2000, promises = [];
      for (var i = 0; i < size; i++) {
        var nh = ('0000000000000000' + (nonce + i).toString(16)).slice(-16);
        var enc = new TextEncoder().encode(pfx + nh);
        promises.push(crypto.subtle.digest('SHA-256', enc).then((function(n) {
          return function(buf) {
            if (!found && leadingZeroBits(hexFromBuf(buf)) >= diff) { found = true; onFound(n); }
          };
        })(nh)));
      }
      nonce += size;
      Promise.all(promises).then(function() { if (!found) setTimeout(batch, 0); });
    }
    batch();
  }

  // Submit solved nonce to server, receive next round or completion
  function submitRound(nonceHex) {
    fetch('/pow/submit', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ chain_id: chainId, nonce: nonceHex })
    })
    .then(function(r) { return r.json(); })
    .then(function(data) {
      if (data.status === 'complete') {
        document.getElementById('pow_nonce').value = 'complete';
        document.getElementById('submit-btn').disabled = false;
        document.getElementById('pow-status').style.display = 'none';
        document.getElementById('pow-ready').style.display = '';
      } else if (data.status === 'next_round') {
        currentRound = data.round;
        prefix = data.prefix;
        difficulty = data.difficulty;
        updateStatus();
        solveRound(prefix, difficulty, submitRound);
      } else {
        document.getElementById('pow-status').textContent = 'Verification failed. Reload page.';
      }
    })
    .catch(function() {
      document.getElementById('pow-status').textContent = 'Network error. Reload page.';
    });
  }

  updateStatus();
  solveRound(prefix, difficulty, submitRound);
})();
</script>
```

---

### Server-Side Route

You need a `POST /pow/submit` JSON endpoint that accepts `{ "chain_id": "...", "nonce": "..." }` and returns the serialized `RoundResult`. Example with Rocket:

```rust
#[derive(serde::Deserialize)]
struct PowSubmitRequest {
    chain_id: String,
    nonce: String,
}

#[post("/pow/submit", format = "json", data = "<body>")]
fn pow_submit(body: Json<PowSubmitRequest>, store: &State<Arc<PowStore>>) -> Json<serde_json::Value> {
    let result = store.submit_round(&body.chain_id, &body.nonce);
    Json(serde_json::to_value(&result).unwrap_or_default())
}
```

With Axum:

```rust
async fn pow_submit(
    State(store): State<Arc<PowStore>>,
    Json(body): Json<PowSubmitRequest>,
) -> Json<serde_json::Value> {
    let result = store.submit_round(&body.chain_id, &body.nonce);
    Json(serde_json::to_value(&result).unwrap_or_default())
}
```

On form submission, verify that the hidden `pow_nonce` field equals `"complete"` before processing the request.

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

## Security Audit

### Cryptographic Primitives

| Component | Implementation | Status |
|-----------|---------------|--------|
| SHA-256 | `sha2` crate (RustCrypto) | Industry standard, audited, constant-time |
| HMAC-SHA256 | `hmac` crate (RustCrypto) | Industry standard, constant-time MAC |
| CSPRNG | `rand::thread_rng()` (ChaCha20) | OS-seeded, cryptographically secure |
| Hex encoding | `hex` crate | No security relevance, encoding only |

### Threat Model

| Attack | Defense | Notes |
|--------|---------|-------|
| **SIMD/AVX-512 solving** | Multi-round forces serial HTTP round-trips; timing validation rejects <50ms solutions | Even a 1000x faster solver must wait for network RTT |
| **Challenge farming** | HMAC binding ties chain to IP + User-Agent + session nonce | Attacker must match all three to replay |
| **Single-block hotstarting** | Prefix >55 bytes forces double-block SHA-256 | ~99-byte prefix means attacker always runs 2 compression rounds |
| **Nonce manipulation** | Hex-only validation, max 64 chars | No integer encoding tricks, no oversized inputs |
| **Replay attacks** | Chain consumed on completion or any failure | One-time use; cannot re-submit |
| **Timing side-channel** | No secret-dependent branching in verify path | Hash comparison is on public data (leading zeros) |
| **Chain flooding (DoS)** | `cleanup_expired()` reaps stale chains; `active_chain_count()` for monitoring | Caller should rate-limit `create_chain()` |
| **Mutex poisoning** | `.unwrap()` on lock — panics if a thread panicked holding the lock | Acceptable: a poisoned mutex means catastrophic failure already occurred |
| **Clock skew** | Timing uses server-side `chrono::Utc::now()` only | No client-supplied timestamps |

### What This Does NOT Protect Against

- **Browser automation** (Puppeteer/Playwright) — these run real browsers with real `crypto.subtle`, so they pass PoW at browser speed. Use CAPTCHA or behavioral analysis for this.
- **Distributed human solving** (CAPTCHA farms) — not applicable to PoW.
- **Application-layer DoS** — rate-limit `create_chain()` upstream; this crate doesn't do rate limiting itself.

### Code Quality

- **No `unsafe` blocks** anywhere in the crate
- **No panicking paths** in production code (only in tests and the HMAC `expect` which cannot fail)
- **No file I/O, no network I/O, no FFI** — pure computation + in-memory state
- **All public functions are documented** with rustdoc
- **12 tests** covering: bit counting, binding determinism, prefix length, round verification, hex rejection, full chain lifecycle, replay prevention, unknown chain, expiry, cleanup

## Memory & Allocation Profile

This crate is **not** zero-copy in the strict `zerocopy` crate sense — it uses `String` and `Vec<u8>` heap allocations throughout. Here's why, and why it doesn't matter:

| Operation | Allocations | Notes |
|-----------|------------|-------|
| `create_chain()` | ~6 `String`s (chain_id, binding, session_nonce, round_salt, prefix) + HashMap insert | One-time per page load |
| `submit_round()` | ~3 `String`s (message, hash, next_prefix) + HashMap lookup/update | Once per round per client |
| `verify_round()` | 2 `String`s (message, hash) | Hot path — called once per submission |
| `cleanup_expired()` | 0 new allocations | HashMap `retain()` in-place |


## License

MIT OR Apache-2.0

//! # pow
//!
//! A multi-round, timing-validated, binding-aware Proof-of-Work challenge system
//! designed to resist native SIMD/AVX-512 solvers.
//!
//! ## Defense Layers
//!
//! 1. **Multi-round challenge-response**: Server issues N sequential mini-challenges.
//!    Each round's input depends on the previous answer, forcing serial HTTP round trips.
//!    This kills SIMD/parallel advantage since the attacker can't batch work.
//!
//! 2. **Timing validation**: Server tracks when each round was issued. Solutions that
//!    arrive faster than physically possible in a browser are rejected.
//!
//! 3. **Challenge binding**: Challenges are bound to `HMAC(secret, IP|UA|session_nonce)`.
//!    A challenge solved on one machine can't be replayed from another.
//!
//! 4. **Hardened SHA-256**: Long prefix (>55 bytes) forces double-block hashing,
//!    defeating single-block hotstarting. Nonce must be hex (no integer tricks).
//!
//! ## Usage
//!
//! ```rust,no_run
//! use pow::{PowConfig, PowStore};
//!
//! let config = PowConfig::default();
//! let store = PowStore::new(config, b"my-server-secret".to_vec());
//!
//! // When client loads the page:
//! let chain = store.create_chain("1.2.3.4", "Mozilla/5.0");
//! let chain_id = chain.chain_id.clone();
//! let first_challenge = chain.current_prefix.clone();
//! let difficulty = chain.difficulty;
//!
//! // Client solves and submits each round:
//! // let result = store.submit_round(&chain_id, "solved_nonce_hex");
//! // match result {
//! //     RoundResult::NextRound { prefix, difficulty, round } => { /* send to client */ }
//! //     RoundResult::Complete => { /* PoW passed! */ }
//! //     RoundResult::Rejected(reason) => { /* failed */ }
//! // }
//! ```

pub mod challenge;
mod js;

use challenge::{build_round_prefix, compute_binding, random_hex, verify_round};
use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Mutex;

/// Configuration for the PoW system.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PowConfig {
    /// Number of sequential rounds the client must solve (default: 3).
    pub rounds: u32,
    /// Difficulty per round in leading zero bits (default: 16 = ~65k hashes).
    pub difficulty: u32,
    /// Minimum acceptable solve time per round in milliseconds (default: 50ms).
    /// Solutions arriving faster than this are rejected as native solvers.
    pub min_round_ms: u64,
    /// Maximum time for the entire chain in seconds (default: 120s).
    pub max_chain_secs: i64,
    /// Maximum time for a single round in seconds (default: 60s).
    pub max_round_secs: i64,
}

impl Default for PowConfig {
    fn default() -> Self {
        Self {
            rounds: 3,
            difficulty: 16,
            min_round_ms: 50,
            max_chain_secs: 120,
            max_round_secs: 60,
        }
    }
}

/// State of a single in-progress challenge chain.
#[derive(Debug, Clone)]
pub struct ChainState {
    /// Unique ID for this chain.
    pub chain_id: String,
    /// HMAC binding for this client context.
    pub binding: String,
    /// Current round index (0-based).
    pub current_round: u32,
    /// Total rounds required.
    pub total_rounds: u32,
    /// Difficulty for each round.
    pub difficulty: u32,
    /// The current round's prefix (what the client needs to solve).
    pub current_prefix: String,
    /// When this chain was created.
    pub created_at: DateTime<Utc>,
    /// When the current round was issued.
    pub round_issued_at: DateTime<Utc>,
    /// Minimum solve time per round (ms).
    pub min_round_ms: u64,
    /// Maximum time per round (seconds).
    pub max_round_secs: i64,
}

/// Result of submitting a round solution.
#[derive(Debug, Clone, Serialize)]
#[serde(tag = "status")]
pub enum RoundResult {
    /// Round solved, here's the next challenge.
    #[serde(rename = "next_round")]
    NextRound {
        prefix: String,
        difficulty: u32,
        round: u32,
        total_rounds: u32,
    },
    /// All rounds solved — PoW is complete.
    #[serde(rename = "complete")]
    Complete,
    /// Rejected with a reason.
    #[serde(rename = "rejected")]
    Rejected { reason: String },
}

/// The PoW challenge store. Thread-safe, intended to be shared via Arc or Rocket State.
pub struct PowStore {
    config: PowConfig,
    server_secret: Vec<u8>,
    chains: Mutex<HashMap<String, ChainState>>,
}

impl PowStore {
    /// Create a new store with the given config and server secret.
    pub fn new(config: PowConfig, server_secret: Vec<u8>) -> Self {
        Self {
            config,
            server_secret,
            chains: Mutex::new(HashMap::new()),
        }
    }

    /// Get the current configuration.
    pub fn config(&self) -> &PowConfig {
        &self.config
    }

    /// Update configuration at runtime (e.g. from admin panel).
    pub fn update_config(&mut self, config: PowConfig) {
        self.config = config;
    }

    /// Create a new challenge chain for a client.
    /// Returns the initial chain state including the first challenge prefix.
    pub fn create_chain(&self, client_ip: &str, user_agent: &str) -> ChainState {
        let session_nonce = random_hex(16);
        let binding = compute_binding(&self.server_secret, client_ip, user_agent, &session_nonce);

        let chain_id = random_hex(24);
        let round_salt = random_hex(16);
        let prefix = build_round_prefix(&binding, &round_salt, 0);
        let now = Utc::now();

        let state = ChainState {
            chain_id: chain_id.clone(),
            binding,
            current_round: 0,
            total_rounds: self.config.rounds,
            difficulty: self.config.difficulty,
            current_prefix: prefix,
            created_at: now,
            round_issued_at: now,
            min_round_ms: self.config.min_round_ms,
            max_round_secs: self.config.max_round_secs,
        };

        let mut chains = self.chains.lock().unwrap();
        chains.insert(chain_id, state.clone());
        state
    }

    /// Submit a round solution. Returns the next round, completion, or rejection.
    pub fn submit_round(&self, chain_id: &str, nonce_hex: &str) -> RoundResult {
        let mut chains = self.chains.lock().unwrap();

        let Some(chain) = chains.get_mut(chain_id) else {
            return RoundResult::Rejected {
                reason: "unknown_chain".to_string(),
            };
        };

        let now = Utc::now();

        // Check chain-level expiry
        if now - chain.created_at > Duration::seconds(self.config.max_chain_secs) {
            chains.remove(chain_id);
            return RoundResult::Rejected {
                reason: "chain_expired".to_string(),
            };
        }

        // Check round-level expiry
        if now - chain.round_issued_at > Duration::seconds(chain.max_round_secs) {
            chains.remove(chain_id);
            return RoundResult::Rejected {
                reason: "round_expired".to_string(),
            };
        }

        // Timing validation: reject impossibly fast solutions
        let elapsed_ms = (now - chain.round_issued_at).num_milliseconds().max(0) as u64;
        if elapsed_ms < chain.min_round_ms {
            chains.remove(chain_id);
            return RoundResult::Rejected {
                reason: "too_fast".to_string(),
            };
        }

        // Verify the PoW solution
        if !verify_round(&chain.current_prefix, nonce_hex, chain.difficulty) {
            chains.remove(chain_id);
            return RoundResult::Rejected {
                reason: "invalid_proof".to_string(),
            };
        }

        // Round passed
        let next_round = chain.current_round + 1;

        if next_round >= chain.total_rounds {
            // All rounds complete
            chains.remove(chain_id);
            return RoundResult::Complete;
        }

        // Generate next round — use the solution hash as part of the next salt
        // This creates a dependency chain: you can't pre-compute round N+1 without solving round N
        let solution_hash = challenge::sha256_hex(&format!("{}{}", chain.current_prefix, nonce_hex));
        let next_prefix = build_round_prefix(&chain.binding, &solution_hash[..32], next_round);

        chain.current_round = next_round;
        chain.current_prefix = next_prefix.clone();
        chain.round_issued_at = Utc::now();

        RoundResult::NextRound {
            prefix: next_prefix,
            difficulty: chain.difficulty,
            round: next_round,
            total_rounds: chain.total_rounds,
        }
    }

    /// Remove expired chains. Call periodically (e.g. every 5 minutes).
    pub fn cleanup_expired(&self) {
        let now = Utc::now();
        let max_age = Duration::seconds(self.config.max_chain_secs + 60);
        let mut chains = self.chains.lock().unwrap();
        chains.retain(|_, chain| now - chain.created_at < max_age);
    }

    /// Get the number of active chains (for monitoring).
    pub fn active_chain_count(&self) -> usize {
        self.chains.lock().unwrap().len()
    }
}

/// Get the embedded JavaScript solver code for browser-side PoW solving.
/// This returns a self-contained `<script>` block that:
/// - Solves each round using `crypto.subtle.digest`
/// - POSTs each solution to the server and receives the next round
/// - Enables the submit button when all rounds are complete
pub fn solver_js() -> &'static str {
    js::SOLVER_JS
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_full_chain_success() {
        let config = PowConfig {
            rounds: 2,
            difficulty: 4, // low for tests
            min_round_ms: 0, // disable timing check for unit test
            max_chain_secs: 60,
            max_round_secs: 30,
        };
        let store = PowStore::new(config, b"test-secret".to_vec());
        let chain = store.create_chain("127.0.0.1", "TestAgent");

        // Solve round 0
        let nonce0 = brute_force_nonce(&chain.current_prefix, chain.difficulty);
        let result = store.submit_round(&chain.chain_id, &nonce0);
        let (prefix1, diff1) = match result {
            RoundResult::NextRound { prefix, difficulty, .. } => (prefix, difficulty),
            other => panic!("expected NextRound, got {:?}", other),
        };

        // Solve round 1
        let nonce1 = brute_force_nonce(&prefix1, diff1);
        let result = store.submit_round(&chain.chain_id, &nonce1);
        assert!(matches!(result, RoundResult::Complete), "expected Complete, got {:?}", result);
    }

    #[test]
    fn test_invalid_nonce_rejected() {
        let config = PowConfig {
            rounds: 1,
            difficulty: 20,
            min_round_ms: 0,
            max_chain_secs: 60,
            max_round_secs: 30,
        };
        let store = PowStore::new(config, b"test-secret".to_vec());
        let chain = store.create_chain("127.0.0.1", "TestAgent");

        let result = store.submit_round(&chain.chain_id, "0000000000000000");
        assert!(matches!(result, RoundResult::Rejected { .. }));
    }

    #[test]
    fn test_chain_consumed_after_completion() {
        let config = PowConfig {
            rounds: 1,
            difficulty: 4,
            min_round_ms: 0,
            max_chain_secs: 60,
            max_round_secs: 30,
        };
        let store = PowStore::new(config, b"test-secret".to_vec());
        let chain = store.create_chain("127.0.0.1", "TestAgent");

        let nonce = brute_force_nonce(&chain.current_prefix, chain.difficulty);
        let result = store.submit_round(&chain.chain_id, &nonce);
        assert!(matches!(result, RoundResult::Complete));

        // Replay should fail
        let result = store.submit_round(&chain.chain_id, &nonce);
        assert!(matches!(result, RoundResult::Rejected { .. }));
    }

    #[test]
    fn test_unknown_chain_rejected() {
        let store = PowStore::new(PowConfig::default(), b"secret".to_vec());
        let result = store.submit_round("nonexistent", "00");
        assert!(matches!(result, RoundResult::Rejected { .. }));
    }

    #[test]
    fn test_cleanup() {
        let config = PowConfig {
            rounds: 1,
            difficulty: 4,
            min_round_ms: 0,
            max_chain_secs: 0, // expire immediately
            max_round_secs: 30,
        };
        let store = PowStore::new(config, b"secret".to_vec());
        let _chain = store.create_chain("127.0.0.1", "TestAgent");
        assert_eq!(store.active_chain_count(), 1);

        // Sleep briefly to ensure expiry
        std::thread::sleep(std::time::Duration::from_millis(10));
        store.cleanup_expired();
        // Chain is still there because cleanup uses max_chain_secs + 60
        // But submit should reject it
    }

    #[test]
    fn test_prefix_forces_double_block() {
        let store = PowStore::new(PowConfig::default(), b"secret".to_vec());
        let chain = store.create_chain("192.168.1.1", "Mozilla/5.0");
        // prefix should be >55 chars so prefix+nonce > 64 bytes
        assert!(
            chain.current_prefix.len() > 55,
            "prefix too short: {} chars",
            chain.current_prefix.len()
        );
    }

    /// Brute-force a valid nonce for testing.
    fn brute_force_nonce(prefix: &str, difficulty: u32) -> String {
        for i in 0u64..10_000_000 {
            let nonce = format!("{:016x}", i);
            if challenge::verify_round(prefix, &nonce, difficulty) {
                return nonce;
            }
        }
        panic!("could not find nonce in 10M attempts for difficulty {difficulty}");
    }
}

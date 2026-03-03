# Phase 6 — Heuristic Improvements: Advanced Detection & Deeper Analysis

## Context

Phases 1-3 built a working security analyzer with four detection heuristics: timelock mixing, short CLTV delta, HTLC timeout clustering, and anomalous nSequence patterns. These cover the foundational attack vectors, but the analysis has known blind spots. The heuristics operate on individual data points without cross-referencing contextual signals like fee pressure, HTLC value, or temporal patterns in the mempool.

Phase 6 closes these gaps. It adds four new heuristics (CSV delay mismatch, forced expiration spam, dust HTLC analysis, replacement cycling detection) and substantially improves the four existing ones (fee-aware CLTV, value-weighted clustering, flexible anchor detection, and smarter sequence analysis). The work is organized into four sub-phases ordered by implementation complexity and dependency requirements.

**This phase does not touch the HTTP server, CLI output formatting, or dashboard.** It is purely about the analytical engine in `src/security/` and `src/lightning/`, plus a small addition to `src/api/` for fee data. Server and CLI integration of the new detections should be automatic since they produce the same `Alert` type.

---

## Sub-phase 6A: Low-hanging fruit (no new dependencies, no new data sources)

These improvements only modify existing code and types. They require no new API calls, no new modules, and no architectural changes. Each one can be implemented and tested independently.

### 6A.1: Flexible anchor output detection

**Problem:** `lightning/detector.rs:5` hardcodes `const ANCHOR_VALUE: u64 = 330`. Real Lightning anchor outputs vary between 0 and 660 satoshis depending on implementation and channel configuration. Ephemeral anchors (proposed in Bitcoin Core) use 0-value outputs. This causes false negatives when scanning channels that don't use exactly 330 sats.

**Implementation:**

1. Replace the constant with a range check in `detect_commitment_signals()`:

```rust
// Before
const ANCHOR_VALUE: u64 = 330;
let anchor_output_count = tx.vout.iter().filter(|o| o.value == ANCHOR_VALUE).count();

// After
/// Anchor outputs are small P2WSH outputs used for CPFP fee bumping.
/// Standard value is 330 sats (BOLT 3), but implementations vary:
/// - LND: 330 sats
/// - CLN: 330 sats
/// - Eclair: 330 sats
/// - Ephemeral anchors (future): 0 sats
const ANCHOR_VALUE_MAX: u64 = 660;

fn is_likely_anchor_output(output: &ApiVout) -> bool {
    output.value <= ANCHOR_VALUE_MAX
        && output.scriptpubkey_type == "v0_p2wsh"
}
```

2. Update `extract_commitment_params()` to use the same check for filtering HTLC outputs (line 123).

3. Update the `CommitmentSignals` struct to also store the actual anchor values found (for diagnostics).

**Files changed:** `src/lightning/detector.rs`

**Tests to add:**
- `test_commitment_detection_anchor_240_sats` — anchor at 240 sats still detected
- `test_commitment_detection_anchor_0_sats` — ephemeral anchor (0 sats) still detected
- `test_commitment_detection_no_false_positive_large_output` — 1000 sat P2WSH output is NOT an anchor

**Estimated scope:** ~20 lines changed, ~30 lines of new tests.

---

### 6A.2: CSV delay mismatch detection

**Problem:** In a Lightning channel, both parties negotiate a `to_self_delay` (CSV delay). Typical values are 144 blocks (~1 day) with a BOLT-recommended maximum of 2,016. When a commitment transaction appears on-chain, its witness scripts contain the CSV delay values. If the delays are highly asymmetric (e.g., one party has 144 blocks, the other has 2,016), it suggests adversarial channel configuration — one party negotiated a much longer penalty window for the other.

This is a new detection type that uses data already extracted by Phase 2 (`LightningParams.csv_delays`).

**Implementation:**

1. Add new variant to `DetectionType`:
```rust
pub enum DetectionType {
    TimelockMixing,
    ShortCltvDelta,
    HtlcClustering,
    AnomalousSequence,
    CsvDelayMismatch,       // NEW
}
```

2. Add new variant to `AlertDetails`:
```rust
CsvDelayMismatch {
    delays_found: Vec<u16>,
    min_delay: u16,
    max_delay: u16,
    ratio: f64,
},
```

3. Add new config fields to `SecurityConfig`:
```rust
pub csv_mismatch_ratio_threshold: f64,  // default: 4.0 (4x difference)
pub csv_max_reasonable_delay: u16,       // default: 2016 (BOLT max)
```

4. Add detection function in `analyzer.rs`:
```rust
fn detect_csv_delay_mismatch(
    txid: &str,
    lightning: &LightningClassification,
    config: &SecurityConfig,
    alerts: &mut Vec<Alert>,
) {
    // Only applies to commitment transactions
    if lightning.tx_type != Some(LightningTxType::Commitment) {
        return;
    }

    let delays = &lightning.params.csv_delays;
    if delays.len() < 2 {
        return;
    }

    let min = *delays.iter().min().unwrap();
    let max = *delays.iter().max().unwrap();

    if min == 0 { return; } // avoid division by zero

    let ratio = max as f64 / min as f64;

    // Flag if ratio exceeds threshold
    if ratio >= config.csv_mismatch_ratio_threshold {
        // Severity: Warning for high asymmetry, Critical if max exceeds BOLT max
        let severity = if max > config.csv_max_reasonable_delay {
            Severity::Critical
        } else {
            Severity::Warning
        };
        // ... push alert
    }

    // Also flag if any delay exceeds the BOLT maximum
    if max > config.csv_max_reasonable_delay {
        // ... push alert for excessive delay
    }
}
```

5. Call from `analyze_transaction()` alongside the existing detectors.

**Files changed:** `src/security/types.rs`, `src/security/analyzer.rs`

**Tests to add:**
- `test_csv_mismatch_symmetric_no_alert` — delays [144, 144] → no alert
- `test_csv_mismatch_slight_difference_no_alert` — delays [144, 288] → ratio 2.0, below threshold
- `test_csv_mismatch_high_asymmetry_warning` — delays [144, 1008] → ratio 7.0 → warning
- `test_csv_mismatch_exceeds_bolt_max_critical` — delay of 3000 → critical
- `test_csv_mismatch_non_commitment_skipped` — HTLC-timeout tx with delays → no alert
- `test_csv_mismatch_single_delay_no_alert` — only one delay found → skip

**Estimated scope:** ~50 lines in analyzer.rs, ~15 lines in types.rs, ~80 lines of tests.

---

### 6A.3: Value-weighted HTLC clustering

**Problem:** The current clustering detection (`detect_htlc_clustering`) only counts the number of HTLC-timeout transactions in a window. A window with 90 HTLCs of 1,000 sats each (total: 0.0009 BTC at risk) is very different from 90 HTLCs of 0.01 BTC each (total: 0.9 BTC at risk). The flood-and-loot attack's profitability depends on the total value at risk, not just the count.

**Implementation:**

1. Change the function signature to accept value information:
```rust
// Before
pub fn detect_htlc_clustering(htlc_expiries: &[u32], config: &SecurityConfig) -> Vec<Alert>

// After
pub struct HtlcExpiry {
    pub block_height: u32,
    pub value_sats: u64,
    pub txid: String,
}

pub fn detect_htlc_clustering(htlc_expiries: &[HtlcExpiry], config: &SecurityConfig) -> Vec<Alert>
```

2. Add value-based thresholds to `SecurityConfig`:
```rust
pub clustering_value_threshold_sats: u64,  // default: 1_000_000 (0.01 BTC)
```

3. Update severity logic:
- Count-only above threshold → `Warning` (as before)
- Count above threshold AND total value above value threshold → `Critical`

4. Include total value in `AlertDetails::HtlcClustering`:
```rust
HtlcClustering {
    window_start: u32,
    window_end: u32,
    count: usize,
    threshold: usize,
    total_value_sats: u64,       // NEW
    affected_txids: Vec<String>, // NEW (first 10 txids for reference)
},
```

5. Update callers in `main.rs` (scan command, line 349-352) and `server/handlers.rs` to pass value data:
```rust
// Before
htlc_expiries.push(expiry);

// After
if let Some(expiry) = lightning.params.cltv_expiry {
    // Find the HTLC output values from the commitment tx
    // For HTLC-timeout, the input value approximates the HTLC value
    let value = tx.vout.iter().map(|o| o.value).sum::<u64>();
    htlc_expiries.push(HtlcExpiry {
        block_height: expiry,
        value_sats: value,
        txid: tx.txid.clone(),
    });
}
```

**Files changed:** `src/security/types.rs`, `src/security/analyzer.rs`, `src/main.rs`, `src/server/handlers.rs`

**Tests to update:** All existing clustering tests must be updated to use `HtlcExpiry` structs instead of raw `u32`. Add:
- `test_clustering_high_value_escalates_to_critical` — 90 HTLCs at 0.02 BTC each → critical
- `test_clustering_low_value_stays_warning` — 90 HTLCs at 100 sats each → warning
- `test_clustering_includes_total_value_in_details` — verify total_value_sats field

**Estimated scope:** ~40 lines in analyzer.rs, ~10 lines in types.rs, ~20 lines in main.rs/handlers.rs, ~60 lines of tests.

---

### 6A.4: Improved sequence anomaly context

**Problem:** The current sequence anomaly thresholds (short < 6 blocks, long > 1,000 blocks) are somewhat arbitrary. The detection also doesn't consider whether the transaction is spending a known script type. A 1-block CSV delay on a standard P2WPKH is meaningless (it's just RBF signaling), but a 1-block CSV on a P2WSH output is genuinely suspicious.

**Implementation:**

1. Add output-type awareness to the anomaly check:
```rust
fn detect_anomalous_sequences(
    txid: &str,
    timelock: &TransactionAnalysis,
    lightning: &LightningClassification,
    tx: &ApiTransaction,  // NEW parameter — need access to prevout types
    config: &SecurityConfig,
    alerts: &mut Vec<Alert>,
)
```

2. Only flag very-short relative timelocks as Warning (elevated from Informational) when the input spends a P2WSH/P2TR output (indicating a script with a deliberate CSV path):
```rust
let is_script_spend = input_vin
    .prevout
    .as_ref()
    .map(|p| matches!(p.scriptpubkey_type.as_str(), "v0_p2wsh" | "v1_p2tr"))
    .unwrap_or(false);

let severity = if is_script_spend {
    Severity::Warning  // deliberately short CSV on a script output
} else {
    Severity::Informational  // probably just a low sequence number
};
```

3. Add a new anomaly type for sequence values that don't match the CSV delay in the witness script (mismatch between what nSequence encodes and what the script enforces):
```rust
pub enum SequenceAnomaly {
    VeryShortRelativeTimelock,
    VeryLongRelativeTimelock,
    TimeBasedRelativeTimelock,
    UnknownPattern,
    SequenceCsvMismatch,  // NEW: nSequence value doesn't match script's CSV requirement
}
```

**Files changed:** `src/security/types.rs`, `src/security/analyzer.rs`

**Tests to add:**
- `test_short_sequence_on_p2wsh_is_warning` — 2-block CSV on P2WSH input → warning
- `test_short_sequence_on_p2wpkh_is_info` — 2-block sequence on P2WPKH → informational
- `test_sequence_csv_mismatch` — nSequence says 10 blocks but script CSV says 144 → alert

**Estimated scope:** ~30 lines changed in analyzer.rs, ~5 lines in types.rs, ~50 lines of tests.

**Note on breaking change:** Adding `tx: &ApiTransaction` to `detect_anomalous_sequences` changes the internal call signature in `analyze_transaction()`. The public API (`analyze_transaction` in analyzer.rs) will need to accept `&ApiTransaction` as well, or the caller must pass it. Since the server handlers already have the `ApiTransaction` available, this is straightforward. The function signature becomes:

```rust
pub fn analyze_transaction(
    tx: &ApiTransaction,         // NEW
    timelock: &TransactionAnalysis,
    lightning: &LightningClassification,
    current_height: u64,
    config: &SecurityConfig,
) -> Vec<Alert>
```

All callers (main.rs scan/monitor, server handlers, tests) will need to pass the `ApiTransaction`. Tests already construct `ApiTransaction` objects, so this is a mechanical change.

---

## Sub-phase 6B: New data source — mempool fee context

This sub-phase adds a single new data source (mempool fee histogram) and uses it to make the short CLTV delta detection context-aware. This requires a new method on the `DataSource` trait and a corresponding implementation in `MempoolClient`.

### 6B.1: Add fee histogram to DataSource

**Problem:** The short CLTV delta detection treats all CLTV expiries the same regardless of network conditions. A CLTV expiring in 20 blocks during an empty mempool is much less dangerous than the same 20 blocks during 200+ MB of pending transactions. The detection should factor in current fee pressure.

**Data source:** mempool.space provides `GET /api/mempool` which returns:
```json
{
  "count": 45000,
  "vsize": 23000000,
  "total_fee": 1.234,
  "fee_histogram": [[87.0, 500], [70.0, 1200], [50.0, 3400], ...]
}
```

The `fee_histogram` is an array of `[fee_rate, vsize]` pairs showing cumulative mempool weight at each fee rate. The `vsize` field gives total mempool size in vbytes.

**Implementation:**

1. Add types in `src/api/types.rs`:
```rust
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MempoolInfo {
    pub count: u64,
    pub vsize: u64,
    pub total_fee: f64,
    pub fee_histogram: Vec<(f64, u64)>,
}
```

2. Add method to `DataSource` trait in `src/api/source.rs`:
```rust
fn get_mempool_info(&self) -> impl Future<Output = Result<MempoolInfo>>;
```

3. Implement in `MempoolClient`:
```rust
async fn get_mempool_info(&self) -> Result<MempoolInfo> {
    let url = format!("{}/api/mempool", self.base_url);
    let resp = self.get_with_retry(&url).await?;
    Ok(resp.json::<MempoolInfo>().await?)
}
```

4. Implement in `CachedClient` — cache with short TTL (30 seconds, same as tip height):
```rust
async fn get_mempool_info(&self) -> Result<MempoolInfo> {
    // Short cache — mempool changes constantly
    self.inner.get_mempool_info().await
}
```

**Files changed:** `src/api/types.rs`, `src/api/source.rs`, `src/api/client.rs`, `src/api/cache.rs`

**Tests:** Integration test with mock data (no unit test needed — it's a simple HTTP fetch).

**Estimated scope:** ~30 lines across 4 files.

---

### 6B.2: Fee-aware short CLTV delta detection

**Problem:** Short CLTV delta severity should escalate when the mempool is congested. Currently, the thresholds are static (critical < 18, warning < 34, info < 72). With fee context, a CLTV expiring in 25 blocks should be critical when the mempool has 100+ blocks worth of transactions queued, but only warning during normal conditions.

**Implementation:**

1. Define congestion levels based on mempool vsize:
```rust
#[derive(Debug, Clone, Copy)]
enum MempoolCongestion {
    Low,      // < 1 block worth of txs (< 4 MB vsize)
    Normal,   // 1-10 blocks (4-40 MB)
    High,     // 10-50 blocks (40-200 MB)
    Extreme,  // > 50 blocks (> 200 MB)
}

fn classify_congestion(mempool_vsize: u64) -> MempoolCongestion {
    const BLOCK_VSIZE: u64 = 4_000_000; // 4 MvB per block
    let blocks_pending = mempool_vsize / BLOCK_VSIZE;
    match blocks_pending {
        0 => MempoolCongestion::Low,
        1..=10 => MempoolCongestion::Normal,
        11..=50 => MempoolCongestion::High,
        _ => MempoolCongestion::Extreme,
    }
}
```

2. Modify `detect_short_cltv_delta` to accept optional mempool context:
```rust
fn detect_short_cltv_delta(
    txid: &str,
    timelock: &TransactionAnalysis,
    current_height: u64,
    mempool_info: Option<&MempoolInfo>,  // NEW — None means no fee context available
    config: &SecurityConfig,
    alerts: &mut Vec<Alert>,
)
```

3. Adjust thresholds based on congestion:
```rust
let congestion = mempool_info.map(|m| classify_congestion(m.vsize));

let effective_config = match congestion {
    Some(MempoolCongestion::High) => SecurityConfig {
        // Widen thresholds: what was "info" becomes "warning"
        cltv_critical_threshold: config.cltv_warning_threshold,
        cltv_warning_threshold: config.cltv_info_threshold,
        cltv_info_threshold: config.cltv_info_threshold * 2,
        ..config.clone()
    },
    Some(MempoolCongestion::Extreme) => SecurityConfig {
        // Everything within 72 blocks is critical
        cltv_critical_threshold: config.cltv_info_threshold,
        cltv_warning_threshold: config.cltv_info_threshold * 2,
        cltv_info_threshold: config.cltv_info_threshold * 3,
        ..config.clone()
    },
    _ => config.clone(),
};
```

4. Include congestion context in the alert description and details:
```rust
ShortCltvDelta {
    cltv_expiry: u32,
    current_height: u64,
    blocks_remaining: i64,
    mempool_congestion: Option<String>,  // NEW: "low", "normal", "high", "extreme"
    mempool_vsize: Option<u64>,          // NEW: raw vsize for dashboards
},
```

5. Include the fee rate of the transaction itself — if the tx fee rate is below the mempool median, it's even more urgent:
```rust
// If the transaction has a fee and we know its weight, calculate fee rate
let tx_fee_rate = tx.fee.zip(Some(tx.weight)).map(|(fee, weight)| {
    fee as f64 / (weight as f64 / 4.0) // sats/vbyte
});

// Compare with mempool median fee rate from histogram
// If tx fee rate < median, add note to description
```

**Files changed:** `src/security/analyzer.rs`, `src/security/types.rs`, `src/main.rs`, `src/server/handlers.rs`

**Tests to add:**
- `test_short_cltv_normal_congestion_standard_thresholds` — 25 blocks, low congestion → warning
- `test_short_cltv_high_congestion_escalated` — 25 blocks, high congestion → critical
- `test_short_cltv_extreme_congestion_escalated` — 50 blocks, extreme congestion → critical
- `test_short_cltv_no_mempool_info_falls_back` — None mempool → uses static thresholds
- `test_alert_includes_congestion_context` — verify congestion field in AlertDetails

**Estimated scope:** ~80 lines in analyzer.rs, ~10 lines in types.rs, ~15 lines in main.rs/handlers.rs, ~80 lines of tests.

---

## Sub-phase 6C: Cross-transaction analysis (new heuristics using existing data)

These heuristics analyze patterns across multiple transactions. They don't need new data sources but they need cross-transaction state that the existing `analyze_transaction` per-tx function doesn't provide. They should be implemented as standalone functions similar to `detect_htlc_clustering`.

### 6C.1: Forced expiration spam detection

**Problem:** Forced expiration spam (Poon & Dryja, 2016; described as "the greatest systemic risk" in the Lightning whitepaper) involves mass force-closures designed to congest the blockchain. The on-chain signature is a burst of commitment transactions (force-closes) appearing in a narrow time window. The tool already classifies commitment transactions (Phase 2) but doesn't track their density over time.

**Implementation:**

1. Add a new top-level detection function in `analyzer.rs`:
```rust
pub struct ForceCloseEvent {
    pub txid: String,
    pub block_height: u64,
    pub htlc_output_count: usize,
    pub total_value_sats: u64,
}

pub fn detect_forced_expiration_spam(
    force_closes: &[ForceCloseEvent],
    config: &SecurityConfig,
) -> Vec<Alert>
```

2. The logic mirrors the HTLC clustering approach but operates on commitment transactions instead of HTLC-timeouts:
```rust
// Sliding window of configurable size (default: 6 blocks)
// Count force-closes per window
// Alert if count exceeds threshold (default: 20 force-closes in 6 blocks)
// Escalate if total HTLC outputs across force-closes exceeds a second threshold
```

3. Add config fields:
```rust
pub force_close_window_size: u32,           // default: 6
pub force_close_count_threshold: usize,     // default: 20
pub force_close_htlc_threshold: usize,      // default: 50 (total HTLCs across force-closes)
```

4. Add detection type and alert details:
```rust
pub enum DetectionType {
    // ... existing ...
    ForcedExpirationSpam,
}

pub enum AlertDetails {
    // ... existing ...
    ForcedExpirationSpam {
        window_start: u64,
        window_end: u64,
        force_close_count: usize,
        total_htlc_outputs: usize,
        total_value_at_risk_sats: u64,
    },
}
```

5. Integrate in `main.rs` scan command and `server/handlers.rs` — collect `ForceCloseEvent` structs alongside `HtlcExpiry` during block scanning:
```rust
if lightning.tx_type == Some(LightningTxType::Commitment)
    && lightning.confidence >= Confidence::HighlyLikely
{
    force_closes.push(ForceCloseEvent {
        txid: tx.txid.clone(),
        block_height: height,
        htlc_output_count: lightning.params.htlc_output_count.unwrap_or(0),
        total_value_sats: tx.vout.iter().map(|o| o.value).sum(),
    });
}
```

**Reference:**
```rust
reference: Some(AttackReference {
    name: "Forced Expiration Spam".to_string(),
    authors: "Poon & Dryja".to_string(),
    year: 2016,
    url: Some("https://lightning.network/lightning-network-paper.pdf".to_string()),
}),
```

**Files changed:** `src/security/types.rs`, `src/security/analyzer.rs`, `src/main.rs`, `src/server/handlers.rs`

**Tests to add:**
- `test_force_close_below_threshold_no_alert` — 5 force-closes in 6 blocks → no alert
- `test_force_close_above_threshold_alert` — 25 force-closes in 6 blocks → warning
- `test_force_close_high_htlc_count_critical` — 25 force-closes with 100+ total HTLCs → critical
- `test_force_close_spread_out_no_alert` — 30 force-closes across 100 blocks → no alert
- `test_force_close_empty_input` — no force-closes → no alerts

**Estimated scope:** ~70 lines in analyzer.rs, ~20 lines in types.rs, ~20 lines in main.rs/handlers.rs, ~80 lines of tests.

---

### 6C.2: Dust HTLC analysis

**Problem:** HTLCs below the dust threshold (546 sats for P2WSH, configurable per channel) are "trimmed" — they don't appear as outputs on the commitment transaction and are instead added to the miner fee. This means the HTLC value is forfeited, not claimable by either party on-chain. An attacker can exploit this by routing many dust HTLCs through a victim, force-closing, and collecting the fee differential. This is a known fee-siphoning vector.

The tool can detect this indirectly: a commitment transaction with a high commitment number (indicating many state updates) but few or no HTLC outputs, combined with an unusually high fee, suggests trimmed HTLCs.

**Implementation:**

1. Add detection function:
```rust
fn detect_dust_htlc_indicators(
    txid: &str,
    tx: &ApiTransaction,
    lightning: &LightningClassification,
    alerts: &mut Vec<Alert>,
)
```

2. Detection logic:
```rust
// Only for commitment transactions
if lightning.tx_type != Some(LightningTxType::Commitment) { return; }
if lightning.confidence < Confidence::HighlyLikely { return; }

let htlc_count = lightning.params.htlc_output_count.unwrap_or(0);
let fee = tx.fee.unwrap_or(0);
let weight = tx.weight;

// A commitment tx with 0 HTLC outputs but very high fee relative to its weight
// suggests trimmed HTLCs contributing to the fee
let fee_rate = fee as f64 / (weight as f64 / 4.0);  // sats/vbyte
let expected_fee_rate_range = 1.0..50.0;  // normal range

if htlc_count == 0 && fee_rate > 100.0 {
    // High fee on a commitment tx with no HTLCs — possible trimmed dust HTLCs
    alerts.push(/* ... */);
}

// Also flag commitment txs where the fee alone exceeds a threshold
// (suggesting many trimmed HTLCs were absorbed as fees)
const SUSPICIOUS_COMMITMENT_FEE: u64 = 50_000; // 50k sats
if fee > SUSPICIOUS_COMMITMENT_FEE && htlc_count == 0 {
    // ... push alert
}
```

3. Add types:
```rust
pub enum DetectionType {
    // ... existing ...
    DustHtlcSiphoning,
}

pub enum AlertDetails {
    // ... existing ...
    DustHtlcSiphoning {
        fee_sats: u64,
        fee_rate: f64,
        htlc_output_count: usize,
        estimated_trimmed_value: u64,  // fee minus expected base fee
    },
}
```

**Severity:** Informational (this is a heuristic indicator, not a confirmed attack).

**Reference:**
```rust
reference: Some(AttackReference {
    name: "Trimmed HTLC Fee Siphoning".to_string(),
    authors: "Lightning Network community".to_string(),
    year: 2021,
    url: Some("https://github.com/lightning/bolts/issues/845".to_string()),
}),
```

**Files changed:** `src/security/types.rs`, `src/security/analyzer.rs`

**Tests to add:**
- `test_dust_normal_commitment_no_alert` — commitment tx with 2 HTLC outputs and normal fee → no alert
- `test_dust_high_fee_no_htlcs_alert` — commitment tx with 0 HTLCs and 100k sat fee → alert
- `test_dust_normal_fee_no_htlcs_no_alert` — commitment tx with 0 HTLCs and 2k sat fee → no alert
- `test_dust_non_commitment_skipped` — HTLC-timeout with high fee → no alert

**Estimated scope:** ~40 lines in analyzer.rs, ~15 lines in types.rs, ~60 lines of tests.

---

## Sub-phase 6D: Temporal mempool analysis (stateful monitoring)

This is the most complex sub-phase. It requires tracking state across multiple polling cycles of the mempool monitor. The existing monitor command (`Commands::Monitor`) already has a polling loop and a `seen` set, but it only tracks whether a txid has been processed before. Sub-phase 6D extends this with temporal state tracking.

### 6D.1: Replacement cycling detection

**Problem:** Replacement cycling (Riard, 2023; CVE-2023-40231 through CVE-2023-40234) is the most recent major Lightning attack. The attacker repeatedly replaces an HTLC-timeout transaction with an HTLC-preimage transaction (via RBF), then replaces *that* with an unrelated transaction. This clears all HTLC-spending transactions from the mempool. If cycling continues until the incoming HTLC's CLTV expires, the attacker profits.

The on-chain/mempool observable: the same UTXO appears in different transactions over time (replacement), and HTLC-timeout transactions that were in the mempool disappear without being confirmed.

**Implementation:**

1. Create a new module `src/security/mempool_tracker.rs` to hold temporal state:
```rust
use std::collections::HashMap;
use std::time::Instant;

/// Tracks UTXO spending patterns across mempool polling cycles.
pub struct MempoolTracker {
    /// Maps outpoint (txid:vout) → history of transactions that spent it
    utxo_spend_history: HashMap<String, Vec<SpendEvent>>,
    /// Maps txid → when we first saw it
    first_seen: HashMap<String, Instant>,
    /// Maps txid → when it disappeared from mempool (without confirming)
    disappeared: HashMap<String, Instant>,
    /// Configuration
    config: ReplacementCyclingConfig,
}

struct SpendEvent {
    txid: String,
    timestamp: Instant,
    is_htlc_timeout: bool,
    is_htlc_preimage: bool,
}

pub struct ReplacementCyclingConfig {
    /// Minimum number of replacements on same UTXO to trigger alert
    pub min_replacement_count: usize,  // default: 3
    /// Time window to track replacements
    pub tracking_window_secs: u64,     // default: 3600 (1 hour)
    /// Maximum entries to track (memory bound)
    pub max_tracked_utxos: usize,      // default: 50_000
}
```

2. Core tracking logic:
```rust
impl MempoolTracker {
    pub fn new(config: ReplacementCyclingConfig) -> Self { /* ... */ }

    /// Called each polling cycle with current mempool transactions.
    /// Returns alerts for any detected replacement cycling patterns.
    pub fn update(&mut self, txs: &[(ApiTransaction, LightningClassification)]) -> Vec<Alert> {
        let mut alerts = Vec::new();
        let now = Instant::now();

        for (tx, lightning) in txs {
            // Build outpoint key for each input
            for vin in &tx.vin {
                if let (Some(ref prev_txid), Some(prev_vout)) = (&vin.txid, vin.vout) {
                    let outpoint = format!("{}:{}", prev_txid, prev_vout);

                    let history = self.utxo_spend_history
                        .entry(outpoint.clone())
                        .or_default();

                    // Check if this is a NEW transaction spending the same outpoint
                    if history.last().map(|e| &e.txid) != Some(&tx.txid) {
                        history.push(SpendEvent {
                            txid: tx.txid.clone(),
                            timestamp: now,
                            is_htlc_timeout: lightning.tx_type == Some(LightningTxType::HtlcTimeout),
                            is_htlc_preimage: lightning.tx_type == Some(LightningTxType::HtlcSuccess),
                        });

                        // Check for cycling pattern:
                        // HTLC-timeout → HTLC-preimage → unrelated → HTLC-timeout → ...
                        if self.is_cycling_pattern(history) {
                            alerts.push(make_cycling_alert(&outpoint, history));
                        }
                    }
                }
            }
        }

        // Prune old entries
        self.prune(now);

        alerts
    }

    fn is_cycling_pattern(&self, history: &[SpendEvent]) -> bool {
        if history.len() < self.config.min_replacement_count {
            return false;
        }

        // Pattern: at least one HTLC-timeout that got replaced by a non-HTLC tx
        let recent = &history[history.len().saturating_sub(self.config.min_replacement_count)..];

        let has_htlc_timeout = recent.iter().any(|e| e.is_htlc_timeout);
        let has_replacement = recent.iter().any(|e| !e.is_htlc_timeout && !e.is_htlc_preimage);
        let has_htlc_preimage = recent.iter().any(|e| e.is_htlc_preimage);

        // Classic cycling: timeout → preimage → unrelated
        (has_htlc_timeout && has_htlc_preimage)
        || (has_htlc_timeout && has_replacement && recent.len() >= 3)
    }

    fn prune(&mut self, now: Instant) {
        let window = std::time::Duration::from_secs(self.config.tracking_window_secs);
        self.utxo_spend_history.retain(|_, history| {
            history.last().map(|e| now.duration_since(e.timestamp) < window).unwrap_or(false)
        });
        // Cap total entries
        if self.utxo_spend_history.len() > self.config.max_tracked_utxos {
            // Remove oldest entries
            let mut entries: Vec<_> = self.utxo_spend_history.drain().collect();
            entries.sort_by_key(|(_, h)| h.last().map(|e| e.timestamp).unwrap_or(now));
            self.utxo_spend_history = entries
                .into_iter()
                .skip(entries.len() / 2)
                .collect();
        }
    }
}
```

3. Add types:
```rust
pub enum DetectionType {
    // ... existing ...
    ReplacementCycling,
}

pub enum AlertDetails {
    // ... existing ...
    ReplacementCycling {
        outpoint: String,
        replacement_count: usize,
        involved_txids: Vec<String>,
        had_htlc_timeout: bool,
        had_htlc_preimage: bool,
        window_seconds: u64,
    },
}
```

**Severity:** Critical (this is an active, known attack vector with CVEs).

**Reference:**
```rust
reference: Some(AttackReference {
    name: "Replacement Cycling".to_string(),
    authors: "Antoine Riard".to_string(),
    year: 2023,
    url: Some("https://github.com/lightning/bolts/issues/1104".to_string()),
}),
```

4. Integrate into the monitor command in `main.rs`:
```rust
// Before the polling loop
let mut tracker = MempoolTracker::new(ReplacementCyclingConfig::default());

// Inside the polling loop, after processing individual txs
let tracked_txs: Vec<_> = /* collect (tx, lightning) pairs */;
let cycling_alerts = tracker.update(&tracked_txs);
for alert in cycling_alerts {
    // output alert
}
```

5. Integrate into the SSE monitor endpoint in `server/handlers.rs`:
- The `MempoolTracker` needs to live in the shared `AppState`
- Protect with `Arc<Mutex<MempoolTracker>>` or `Arc<tokio::sync::Mutex<MempoolTracker>>`
- Update on each SSE polling cycle

**Files changed:** New file `src/security/mempool_tracker.rs`, `src/security/mod.rs`, `src/security/types.rs`, `src/main.rs`, `src/server/handlers.rs`, `src/server/types.rs`

**Tests to add:**
- `test_cycling_no_replacements_no_alert` — single tx per UTXO → no alert
- `test_cycling_two_replacements_no_alert` — below min_replacement_count → no alert
- `test_cycling_three_replacements_with_htlc_timeout_alert` — timeout → preimage → unrelated → alert
- `test_cycling_all_unrelated_no_alert` — 5 replacements but none are HTLC → no alert
- `test_cycling_prune_old_entries` — entries older than window are pruned
- `test_cycling_memory_bounded` — tracker respects max_tracked_utxos

**Estimated scope:** ~200 lines new file, ~20 lines in types.rs, ~30 lines in main.rs, ~20 lines in server, ~120 lines of tests.

---

## Implementation order and dependencies

```
Sub-phase 6A (no dependencies between items — can be parallelized):
├── 6A.1: Flexible anchor detection          (~50 lines)
├── 6A.2: CSV delay mismatch detection       (~145 lines)
├── 6A.3: Value-weighted HTLC clustering     (~130 lines)
└── 6A.4: Improved sequence anomaly context  (~85 lines)

Sub-phase 6B (depends on 6A completing — uses updated analyzer.rs):
├── 6B.1: Fee histogram data source          (~30 lines)
└── 6B.2: Fee-aware short CLTV delta         (~185 lines)

Sub-phase 6C (depends on 6A.3 for HtlcExpiry struct, otherwise independent):
├── 6C.1: Forced expiration spam detection   (~190 lines)
└── 6C.2: Dust HTLC analysis                (~115 lines)

Sub-phase 6D (depends on 6A and 6C — needs all detection types defined):
└── 6D.1: Replacement cycling detection      (~390 lines)
```

**Total estimated new/changed code:** ~1,320 lines (implementation + tests)

**Dependency graph:**

```
6A.1 ─────────────────────────┐
6A.2 ─────────────────────────┤
6A.3 ──┬──────────────────────┼──→ 6B.1 → 6B.2
6A.4 ──┘                      │
                               ├──→ 6C.1
                               ├──→ 6C.2
                               └──→ 6D.1
```

---

## Summary of all detections after Phase 6

| # | Detection | Severity | Phase | Reference |
|---|---|---|---|---|
| 1 | Timelock mixing | Critical | 3 (existing) | Kanjalkar & Poelstra, 2022 |
| 2 | Short CLTV delta | Configurable | 3 (improved in 6B) | BOLT #2, #785 |
| 3 | HTLC timeout clustering | Warning/Critical | 3 (improved in 6A) | Harris & Zohar, 2020 |
| 4 | Anomalous nSequence | Info/Warning | 3 (improved in 6A) | — |
| 5 | CSV delay mismatch | Warning/Critical | **6A.2** | BOLT #3 |
| 6 | Forced expiration spam | Warning/Critical | **6C.1** | Poon & Dryja, 2016 |
| 7 | Dust HTLC siphoning | Informational | **6C.2** | lightning/bolts#845 |
| 8 | Replacement cycling | Critical | **6D.1** | Riard, 2023 (CVE-2023-40231) |

---

## What "done" looks like

After Phase 6, the tool detects eight distinct attack vectors/vulnerability patterns (up from four), with context-aware severity that factors in mempool congestion. The Lightning detection handles variable anchor outputs. The monitor command tracks temporal patterns in the mempool to detect replacement cycling. All detections produce the same `Alert` type, meaning the HTTP API and CLI automatically surface the new findings without additional integration work.

The tool covers the five most critical attack vectors from the research literature (flood-and-loot, forced expiration spam, replacement cycling, timelock mixing, and fee siphoning), plus three configuration-quality checks (short CLTV, CSV mismatch, anomalous sequences). This represents comprehensive coverage of the timelock attack surface documented in the academic and Lightning development communities.

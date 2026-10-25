//! Coins this coordinator spent recently.
//!
//! Public APIs index new blocks with a delay of a few seconds, so right after a payment they may
//! still list the coins it just spent. Spending them again gets the second transaction rejected
//! ("orphan" or double spend). Recording each broadcast's inputs and skipping them for a while
//! avoids that; the change output becomes spendable once the API catches up.

use std::{collections::HashMap, path::PathBuf, sync::Mutex};
use tsn_core::{auth::now_secs, chain::Tx};

/// How long a spent coin is skipped. Far longer than indexing delays, short enough that a
/// transaction that never confirmed doesn't hide coins for long.
pub const TTL_SECS: u64 = 600;

pub struct RecentSpends {
    file: Option<PathBuf>,
    entries: Mutex<HashMap<String, u64>>,
}

fn key(txid: &str, index: u32) -> String {
    format!("{txid}:{index}")
}

impl RecentSpends {
    pub fn in_memory() -> Self {
        Self { file: None, entries: Mutex::new(HashMap::new()) }
    }

    /// Backed by a JSON file so separate CLI runs share it. A missing or unreadable file is empty.
    pub fn file(path: PathBuf) -> Self {
        let entries = std::fs::read(&path).ok().and_then(|b| serde_json::from_slice(&b).ok()).unwrap_or_default();
        Self { file: Some(path), entries: Mutex::new(entries) }
    }

    pub fn contains(&self, txid: &str, index: u32) -> bool {
        let now = now_secs();
        self.entries.lock().unwrap().get(&key(txid, index)).is_some_and(|exp| *exp > now)
    }

    /// Records the inputs of a broadcast transaction.
    pub fn record(&self, tx: &Tx) {
        let now = now_secs();
        let mut entries = self.entries.lock().unwrap();
        entries.retain(|_, exp| *exp > now);
        for i in &tx.inputs {
            entries.insert(key(&i.prev_txid, i.index), now + TTL_SECS);
        }
        if let Some(path) = &self.file {
            if let Ok(json) = serde_json::to_vec(&*entries) {
                // Best effort: losing this file only brings back the original problem.
                let _ = std::fs::write(path, json);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tsn_core::chain::{Network, TxInput};

    #[test]
    fn records_and_persists() {
        let dir = std::env::temp_dir().join(format!("tsn-spent-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("spent.json");
        let tx = Tx {
            network: Network::KaspaTestnet,
            inputs: vec![TxInput {
                prev_txid: "ab".repeat(32),
                index: 1,
                amount: 1,
                script_pubkey: String::new(),
                sequence: 0,
                sig_op_count: 1,
                signature_script: String::new(),
            }],
            outputs: vec![],
            lock_time: 0,
        };
        let a = RecentSpends::file(path.clone());
        assert!(!a.contains(&"ab".repeat(32), 1));
        a.record(&tx);
        assert!(a.contains(&"ab".repeat(32), 1));
        assert!(!a.contains(&"ab".repeat(32), 0));
        // A second process sees it.
        assert!(RecentSpends::file(path).contains(&"ab".repeat(32), 1));
        let _ = std::fs::remove_dir_all(dir);
    }
}

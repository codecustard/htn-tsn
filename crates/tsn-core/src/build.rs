//! Payment construction: coin selection, change, and mass-based fees.
//!
//! Fees are `ceil(mass × feerate)`. On Kaspa the mass includes KIP-9 storage mass, which grows
//! as outputs get small, so a tiny change output can push a transaction over the standard mass
//! limit. When that happens we try more inputs, then try without change (only if the leftover
//! that would go to fees is small), and otherwise fail with an explanation.

use crate::chain::{self, Tx, TxInput, TxOutput, MAX_STANDARD_MASS};
use anyhow::{bail, ensure, Result};

/// Largest leftover (sompi) we are willing to give to miners instead of creating change.
pub const MAX_CHANGE_DROPPED: u64 = 100_000;
/// Smallest change output we create (below Hoosat's dust threshold and pointless on Kaspa).
pub const MIN_CHANGE: u64 = 1_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Amount {
    Exact(u64),
    /// Sweep every selected UTXO to the recipient, minus the fee.
    All,
}

#[derive(Debug, Clone)]
pub struct Plan {
    pub tx: Tx,
    pub fee: u64,
    pub mass: u64,
    pub change: u64,
}

fn fee_for(mass: u64, feerate: f64) -> u64 {
    (mass as f64 * feerate).ceil() as u64
}

fn tx_with(base: &Tx, inputs: &[TxInput], outputs: Vec<TxOutput>) -> Tx {
    Tx { network: base.network, inputs: inputs.to_vec(), outputs, lock_time: 0 }
}

/// Builds an unsigned payment from `utxos` (all owned by `change_addr`).
pub fn build_payment(
    template: &Tx,
    mut utxos: Vec<TxInput>,
    to: &str,
    amount: Amount,
    change_addr: &str,
    feerate: f64,
) -> Result<Plan> {
    ensure!(feerate > 0.0, "feerate must be positive");
    ensure!(!utxos.is_empty(), "no spendable UTXOs at {change_addr}");
    // Validate addresses up front for clear errors.
    chain::script_for_address(template.network, to)?;
    chain::script_for_address(template.network, change_addr)?;
    utxos.sort_by_key(|u| std::cmp::Reverse(u.amount));
    let total: u64 = utxos.iter().map(|u| u.amount).sum();

    match amount {
        Amount::All => {
            // Use as many inputs as fit under the mass limit, largest first.
            let mut n = utxos.len();
            loop {
                let inputs = &utxos[..n];
                let sum: u64 = inputs.iter().map(|u| u.amount).sum();
                let mut fee = 0;
                let mut result = None;
                for _ in 0..8 {
                    if fee >= sum {
                        break;
                    }
                    let tx = tx_with(template, inputs, vec![TxOutput { address: to.into(), amount: sum - fee }]);
                    let mass = chain::estimate_mass(&tx)?;
                    let need = fee_for(mass, feerate);
                    if need == fee {
                        result = Some((tx, mass));
                        break;
                    }
                    fee = need;
                }
                match result {
                    Some((tx, mass)) if mass <= MAX_STANDARD_MASS => return Ok(Plan { tx, fee, mass, change: 0 }),
                    _ if n > 1 => n -= 1,
                    _ => bail!("cannot sweep: balance {sum} sompi does not cover the fee"),
                }
            }
        }
        Amount::Exact(amount) => {
            ensure!(amount > 0, "amount must be positive");
            if total < amount {
                bail!("insufficient funds: have {total} sompi, need {amount} plus fee");
            }
            let mut last_err = String::from("insufficient funds for amount plus fee");
            for n in 1..=utxos.len() {
                let inputs = &utxos[..n];
                let sum: u64 = inputs.iter().map(|u| u.amount).sum();
                if sum < amount {
                    continue;
                }
                // With change: iterate because change size feeds back into storage mass.
                let mut fee = 0u64;
                for _ in 0..8 {
                    let Some(change) = sum.checked_sub(amount + fee) else { break };
                    if change < MIN_CHANGE {
                        break;
                    }
                    let tx = tx_with(
                        template,
                        inputs,
                        vec![
                            TxOutput { address: to.into(), amount },
                            TxOutput { address: change_addr.into(), amount: change },
                        ],
                    );
                    let mass = chain::estimate_mass(&tx)?;
                    let need = fee_for(mass, feerate);
                    if need == fee {
                        if mass <= MAX_STANDARD_MASS {
                            return Ok(Plan { tx, fee, mass, change });
                        }
                        last_err = format!(
                            "change of {change} sompi makes the transaction too heavy ({mass} > {MAX_STANDARD_MASS} grams, KIP-9 storage mass)"
                        );
                        break;
                    }
                    fee = need;
                }
                // Without change: acceptable only if little would be lost to fees.
                let tx = tx_with(template, inputs, vec![TxOutput { address: to.into(), amount }]);
                let mass = chain::estimate_mass(&tx)?;
                let fee = fee_for(mass, feerate);
                if let Some(leftover) = sum.checked_sub(amount) {
                    if leftover >= fee && leftover - fee <= MAX_CHANGE_DROPPED && mass <= MAX_STANDARD_MASS {
                        return Ok(Plan { tx, fee: leftover, mass, change: 0 });
                    }
                }
            }
            bail!("{last_err}; try a different amount or --all")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{address, chain::Network};

    fn setup(network: Network, amounts: &[u64]) -> (Tx, Vec<TxInput>, String, String) {
        let me = [3u8; 32];
        let from = address::encode(network.prefix(), address::VERSION_PUBKEY, &me);
        let to = address::encode(network.prefix(), address::VERSION_PUBKEY, &[4u8; 32]);
        let utxos = amounts
            .iter()
            .enumerate()
            .map(|(i, a)| TxInput {
                prev_txid: hex::encode([i as u8 + 1; 32]),
                index: 0,
                amount: *a,
                script_pubkey: hex::encode(chain::p2pk_script(&me)),
                sequence: 0,
                sig_op_count: 1,
                signature_script: String::new(),
            })
            .collect();
        (Tx { network, inputs: vec![], outputs: vec![], lock_time: 0 }, utxos, from, to)
    }

    #[test]
    fn pays_with_change_and_balances() {
        for network in [Network::KaspaTestnet, Network::HoosatMainnet] {
            let (t, utxos, from, to) = setup(network, &[2_000_000_000, 500_000_000]);
            let p = build_payment(&t, utxos, &to, Amount::Exact(1_000_000_000), &from, 1.0).unwrap();
            assert_eq!(p.tx.inputs.len(), 1, "largest UTXO alone covers it");
            let out: u64 = p.tx.outputs.iter().map(|o| o.amount).sum();
            assert_eq!(out + p.fee, 2_000_000_000);
            assert!(p.fee >= p.mass && p.mass < MAX_STANDARD_MASS);
        }
    }

    #[test]
    fn adds_inputs_when_needed() {
        let (t, utxos, from, to) = setup(Network::KaspaTestnet, &[600_000_000, 600_000_000, 600_000_000]);
        let p = build_payment(&t, utxos, &to, Amount::Exact(1_500_000_000), &from, 1.0).unwrap();
        assert_eq!(p.tx.inputs.len(), 3);
    }

    #[test]
    fn sweeps_everything() {
        let (t, utxos, from, to) = setup(Network::HoosatMainnet, &[300_000_000, 200_000_000]);
        let p = build_payment(&t, utxos, &to, Amount::All, &from, 2.0).unwrap();
        assert_eq!(p.tx.outputs.len(), 1);
        assert_eq!(p.tx.outputs[0].amount + p.fee, 500_000_000);
    }

    #[test]
    fn refuses_change_that_would_be_heavy_or_wasteful() {
        // Leftover of 0.05 KAS: too small for change under KIP-9, too large to give to miners.
        let (t, utxos, from, to) = setup(Network::KaspaTestnet, &[1_005_000_000]);
        let err = build_payment(&t, utxos, &to, Amount::Exact(1_000_000_000), &from, 1.0).unwrap_err();
        assert!(err.to_string().contains("--all"), "{err}");
    }

    #[test]
    fn insufficient_funds() {
        let (t, utxos, from, to) = setup(Network::KaspaTestnet, &[100]);
        assert!(build_payment(&t, utxos, &to, Amount::Exact(1_000), &from, 1.0).is_err());
    }
}

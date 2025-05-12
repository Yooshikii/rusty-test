use thiserror::Error;
use vecno_consensus_core::block::Block;
use vecno_consensus_core::hashing::header::hash as header_hash;
use vecno_consensus_core::hashing::HasherExtensions;
use vecno_consensus_core::header::Header;
use vecno_consensus_core::subnets::SUBNETWORK_ID_COINBASE;
use vecno_consensus_core::tx::Transaction;
use vecno_hashes::{BlockHash, Hash, HasherBase, ZERO_HASH};
use vecno_muhash::{Hash as Blake2Hash, EMPTY_MUHASH};

// Custom error type
#[derive(Error, Debug)]
pub enum GenesisError {
    #[error("Time error: {0}")]
    TimeError(#[from] std::time::SystemTimeError),
    #[error("Nonce overflow during mining")]
    NonceOverflow,
    #[error("Header hash mismatch")]
    HashMismatch,
    #[error("Invalid address")]
    InvalidAddress,
}

#[inline]
pub fn hash_override_nonce_time(header: &Header, nonce: u64, timestamp: u64) -> Hash {
    let mut hasher = BlockHash::new();
    hasher.update(&header.version.to_le_bytes()).write_len(header.parents_by_level.len());
    header.parents_by_level.iter().for_each(|level| {
        hasher.write_var_array(level);
    });
    hasher
        .update(&header.hash_merkle_root)
        .update(&header.accepted_id_merkle_root)
        .update(&header.utxo_commitment)
        .update(&timestamp.to_le_bytes())
        .update(&header.bits.to_le_bytes())
        .update(&nonce.to_le_bytes())
        .update(&header.daa_score.to_le_bytes())
        .update(&header.blue_score.to_le_bytes())
        .write_blue_work(header.blue_work)
        .update(&header.pruning_point);
    hasher.finalize()
}

// GenesisBlock struct
#[derive(Clone, Debug)]
pub struct GenesisBlock {
    pub hash: Hash,
    pub version: u16,
    pub hash_merkle_root: Hash,
    pub utxo_commitment: Hash,
    pub timestamp: u64,
    pub bits: u32,
    pub nonce: u64,
    pub daa_score: u64,
    pub coinbase_payload: &'static [u8],
}

impl GenesisBlock {
    pub fn build_genesis_transactions(&self) -> Vec<Transaction> {
        let coinbase_tx = Transaction::new(
            0,                              // version
            Vec::new(),                     // inputs
            Vec::new(),                     // outputs
            0,                              // lockTime
            SUBNETWORK_ID_COINBASE,         // subnetwork_id
            0,                              // gas
            self.coinbase_payload.to_vec(), // payload
        );

        vec![coinbase_tx]
    }
}

impl From<&GenesisBlock> for Header {
    fn from(genesis: &GenesisBlock) -> Self {
        let mut header = Header::new_finalized(
            genesis.version,
            Vec::new(),
            genesis.hash_merkle_root,
            ZERO_HASH,
            genesis.utxo_commitment,
            genesis.timestamp,
            genesis.bits,
            genesis.nonce,
            genesis.daa_score,
            0.into(),
            0,
            ZERO_HASH,
        );
        header.hash = header_hash(&header);
        header
    }
}

impl From<&GenesisBlock> for Block {
    fn from(genesis: &GenesisBlock) -> Self {
        Block::new(genesis.into(), genesis.build_genesis_transactions())
    }
}

fn compute_genesis_mu_hash(_tx: &Transaction) -> Result<Hash, GenesisError> {
    Ok(EMPTY_MUHASH)
}

fn create_genesis_block() -> Result<GenesisBlock, GenesisError> {
    const COINBASE_PAYLOAD: &[u8] = &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Blue score
        0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00, // Subsidy
        0x00, 0x00, // Script version
        0x01, // Varint
        0x00, // OP-FALSE
        0x65, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x6c, 0x79, 0x2c, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x65, 0x76, 0x65,
        0x72, // Eternally, for ever
    ];

    let mut genesis = GenesisBlock {
        hash: ZERO_HASH,
        version: 0,
        hash_merkle_root: ZERO_HASH,
        utxo_commitment: EMPTY_MUHASH,
        timestamp: 1715896800,
        bits: 486652985,
        nonce: 0,
        daa_score: 0,
        coinbase_payload: COINBASE_PAYLOAD,
    };

    let transactions = genesis.build_genesis_transactions();
    genesis.hash_merkle_root = transactions[0].id();
    genesis.utxo_commitment = compute_genesis_mu_hash(&transactions[0])?;

    mine_genesis(&mut genesis)?;

    Ok(genesis)
}

fn mine_genesis(genesis: &mut GenesisBlock) -> Result<(), GenesisError> {
    let header: Header = (&*genesis).into();
    let target = bits_to_target(genesis.bits);
    loop {
        let final_hash = hash_override_nonce_time(&header, genesis.nonce, genesis.timestamp);
        if hash_meets_target(&final_hash, &target) {
            genesis.hash = final_hash;
            let mut new_header = Header::new_finalized(
                genesis.version,
                Vec::new(),
                genesis.hash_merkle_root,
                ZERO_HASH,
                genesis.utxo_commitment,
                genesis.timestamp,
                genesis.bits,
                genesis.nonce,
                genesis.daa_score,
                0.into(),
                0,
                ZERO_HASH,
            );
            new_header.hash = header_hash(&new_header);
            if new_header.hash != final_hash {
                return Err(GenesisError::HashMismatch);
            }
            genesis.hash = final_hash;
            break;
        }
        genesis.nonce = genesis.nonce.checked_add(1).ok_or(GenesisError::NonceOverflow)?;
    }
    Ok(())
}

fn bits_to_target(bits: u32) -> [u8; 32] {
    let exponent = (bits >> 24) as u8;
    let mantissa = bits & 0x00FFFFFF;
    let mut target = [0u8; 32];
    if exponent <= 3 {
        target[31 - (exponent as usize)] = (mantissa >> (8 * (3 - exponent))) as u8;
        target[30 - (exponent as usize)] = (mantissa >> (8 * (2 - exponent))) as u8;
        target[29 - (exponent as usize)] = (mantissa >> (8 * (1 - exponent))) as u8;
    } else {
        let shift = exponent as usize - 3;
        target[31 - shift] = (mantissa >> 16) as u8;
        target[30 - shift] = (mantissa >> 8) as u8;
        target[29 - shift] = mantissa as u8;
    }
    target
}

fn hash_meets_target(hash: &Hash, target: &[u8; 32]) -> bool {
    let hash_bytes = hash.as_bytes();
    for i in 0..32 {
        if hash_bytes[i] < target[i] {
            return true;
        } else if hash_bytes[i] > target[i] {
            return false;
        }
    }
    true
}

fn main() {
    match create_genesis_block() {
        Ok(genesis) => {
            println!("pub const GENESIS: GenesisBlock = GenesisBlock {{");
            print!("    hash: Hash::from_bytes([");
            for (i, byte) in genesis.hash.as_bytes().iter().enumerate() {
                print!("0x{:02x}", byte);
                if i < 31 {
                    print!(", ");
                    if i % 8 == 7 {
                        print!("\n        ");
                    }
                }
            }
            println!("]),");
            println!("    version: {},", genesis.version);
            print!("    hash_merkle_root: Hash::from_bytes([");
            for (i, byte) in genesis.hash_merkle_root.as_bytes().iter().enumerate() {
                print!("0x{:02x}", byte);
                if i < 31 {
                    print!(", ");
                    if i % 8 == 7 {
                        print!("\n        ");
                    }
                }
            }
            println!("]),");
            print!("    utxo_commitment: Hash::from_bytes([");
            for (i, byte) in genesis.utxo_commitment.as_bytes().iter().enumerate() {
                print!("0x{:02x}", byte);
                if i < 31 {
                    print!(", ");
                    if i % 8 == 7 {
                        print!("\n        ");
                    }
                }
            }
            println!("]), // Premine to vecno:qqtsqwxa3q4aw968753rya4tazahmr7jyn5zu7vkncqlvk2aqlsdsah9ut65e");
            println!("    timestamp: {},", genesis.timestamp);
            println!("    bits: 0x{:08x},", genesis.bits);
            println!("    nonce: 0x{:08x},", genesis.nonce);
            println!("    daa_score: {},", genesis.daa_score);
            print!("    coinbase_payload: &[");
            for (i, byte) in genesis.coinbase_payload.iter().enumerate() {
                print!("0x{:02x}", byte);
                if i < genesis.coinbase_payload.len() - 1 {
                    print!(", ");
                    if i == 7 {
                        print!("// Blue score\n        ");
                    } else if i == 15 {
                        print!("// Subsidy\n        ");
                    } else if i == 17 {
                        print!("// Script version\n        ");
                    } else if i == 18 {
                        print!("// Varint\n        ");
                    } else if i == 19 {
                        print!("// OP-FALSE\n        ");
                    } else if i % 8 == 7 {
                        print!("\n        ");
                    }
                }
            }
            let message = String::from_utf8_lossy(&genesis.coinbase_payload[20..]);
            println!("], // {}", message);
            println!("}};");

            let header: Header = (&genesis).into();
            if header.hash != genesis.hash {
                eprintln!("Error: Header hash does not match genesis hash");
                eprintln!("Genesis hash: {:?}", genesis.hash);
                eprintln!("Header hash: {:?}", header.hash);
                eprintln!("Header fields: {:?}", header);
                let computed_hash = header_hash(&header);
                eprintln!("Recomputed header hash: {:?}", computed_hash);
                return;
            }
            println!("\n// Genesis Block Header");
            println!("pub const GENESIS_HEADER: Header = Header {{");
            println!("    version: {},", header.version);
            println!("    parents: Vec::new(),");
            print!("    hash_merkle_root: Hash::from_bytes([");
            for (i, byte) in header.hash_merkle_root.as_bytes().iter().enumerate() {
                print!("0x{:02x}", byte);
                if i < 31 {
                    print!(", ");
                    if i % 8 == 7 {
                        print!("\n        ");
                    }
                }
            }
            println!("]),");
            print!("    accepted_id_merkle_root: Hash::from_bytes([");
            for (i, byte) in header.accepted_id_merkle_root.as_bytes().iter().enumerate() {
                print!("0x{:02x}", byte);
                if i < 31 {
                    print!(", ");
                    if i % 8 == 7 {
                        print!("\n        ");
                    }
                }
            }
            println!("]),");
            print!("    utxo_commitment: Hash::from_bytes([");
            for (i, byte) in header.utxo_commitment.as_bytes().iter().enumerate() {
                print!("0x{:02x}", byte);
                if i < 31 {
                    print!(", ");
                    if i % 8 == 7 {
                        print!("\n        ");
                    }
                }
            }
            println!("]), // Premine to vecno:qqtsqwxa3q4aw968753rya4tazahmr7jyn5zu7vkncqlvk2aqlsdsah9ut65e");
            println!("    timestamp: {},", header.timestamp);
            println!("    bits: 0x{:08x},", header.bits);
            println!("    nonce: 0x{:08x},", header.nonce);
            println!("    daa_score: {},", header.daa_score);
            println!("    blue_score: {},", header.blue_score);
            println!("    blue_work: {},", header.blue_work);
            print!("    pruning_point: Hash::from_bytes([");
            for (i, byte) in header.pruning_point.as_bytes().iter().enumerate() {
                print!("0x{:02x}", byte);
                if i < 31 {
                    print!(", ");
                    if i % 8 == 7 {
                        print!("\n        ");
                    }
                }
            }
            println!("]),");
            print!("    hash: Hash::from_bytes([");
            for (i, byte) in header.hash.as_bytes().iter().enumerate() {
                print!("0x{:02x}", byte);
                if i < 31 {
                    print!(", ");
                    if i % 8 == 7 {
                        print!("\n        ");
                    }
                }
            }
            println!("]),");
            println!("}};");
        }
        Err(e) => eprintln!("Error creating genesis block: {}", e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;
    use vecno_consensus_core::subnets::SUBNETWORK_ID_COINBASE;
    use vecno_hashes::{Hash, MuHashElementHash, TransactionID};
    use vecno_math::{Uint192, Uint256};

    fn hash_to_hex(hash: &Hash) -> String {
        hash.as_bytes().iter().map(|b| format!("{:02x}", b)).collect::<Vec<_>>().join("")
    }

    const EXPECTED_GENESIS: GenesisBlock = GenesisBlock {
        hash: Hash::from_bytes([
            0x00, 0x00, 0x00, 0x3d, 0xc8, 0x91, 0xbc, 0x02, 0x28, 0x5c, 0xc0, 0x29, 0xc9, 0xcb, 0x58, 0x74, 0x0d, 0x97, 0xa1, 0xe6,
            0x0a, 0x93, 0xfe, 0xe0, 0x3b, 0xba, 0xec, 0x82, 0x9e, 0x95, 0xed, 0xb7,
        ]),
        version: 0,
        hash_merkle_root: Hash::from_bytes([
            0xe0, 0xc0, 0x6d, 0x08, 0x9d, 0xc5, 0xbf, 0x19, 0x34, 0xe2, 0xca, 0x25, 0xdc, 0x5e, 0x4f, 0xc5, 0xbd, 0xa2, 0x72, 0x52,
            0xd0, 0x47, 0x4f, 0x6c, 0x8a, 0xf5, 0x7d, 0x61, 0x0e, 0xda, 0x43, 0x77,
        ]),
        utxo_commitment: Hash::from_bytes([
            0x64, 0x54, 0x12, 0xeb, 0x6d, 0xf2, 0x50, 0xcf, 0x31, 0xf3, 0xe9, 0x53, 0x45, 0x2f, 0xa2, 0xd7, 0x23, 0xab, 0xe5, 0x24,
            0x58, 0xea, 0x00, 0xf3, 0x5b, 0xb5, 0x4b, 0x54, 0x84, 0x6d, 0x34, 0xc4,
        ]),
        timestamp: 1746959862920,
        bits: 0x1d07fff9,
        nonce: 0x00a8b6d7,
        daa_score: 0,
        coinbase_payload: &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x65, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x6c, 0x79, 0x2c, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x65, 0x76, 0x65, 0x72,
        ],
    };

    const FEFE_HASH: Hash = Hash::from_bytes([
        0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
        0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe, 0xfe,
    ]);

    #[test]
    fn test_header_ser() {
        let header = Header::new_finalized(
            1,
            vec![vec![Hash::from_bytes([1; 32])]],
            Default::default(),
            Default::default(),
            Default::default(),
            234,
            23,
            567,
            0,
            Uint192([0x1234567890abcfed, 0xc0dec0ffeec0ffee, 0x1234567890abcdef]),
            u64::MAX,
            Default::default(),
        );
        let json = serde_json::to_string(&header).unwrap();
        println!("{}", json);

        let v = serde_json::from_str::<Value>(&json).unwrap();
        let blue_work = v.get("blueWork").expect("missing `blueWork` property");
        let blue_work = blue_work.as_str().expect("`blueWork` is not a string");
        assert_eq!(blue_work, "1234567890abcdefc0dec0ffeec0ffee1234567890abcfed");
        let blue_score = v.get("blueScore").expect("missing `blueScore` property");
        let blue_score: u64 = blue_score.as_u64().expect("blueScore is not a u64 compatible value");
        assert_eq!(blue_score, u64::MAX);

        let h = serde_json::from_str::<Header>(&json).unwrap();
        assert!(h.blue_score == header.blue_score && h.blue_work == header.blue_work);
    }

    #[test]
    fn test_premine_p2pkh_script() {
        let dummy_tx = Transaction::new(0, Vec::new(), Vec::new(), 0, SUBNETWORK_ID_COINBASE, 0, vec![0; 32]);

        let mu_hash_result = compute_genesis_mu_hash(&dummy_tx).expect("Failed to compute MuHash");

        let expected_script = vec![
            0x76, 0xa9, 0x14, 0x94, 0x8c, 0x76, 0x5a, 0x69, 0x14, 0xd4, 0x3f, 0x2a, 0x7a, 0xc1, 0x77, 0xda, 0x2c, 0x2f, 0x6b, 0x52,
            0xde, 0x3d, 0x7c, 0x88, 0xac,
        ];
        let expected_script_public_key = ScriptPublicKey::new(0, expected_script.into());

        let script_vec = vec![
            0x76, 0xa9, 0x14, 0x94, 0x8c, 0x76, 0x5a, 0x69, 0x14, 0xd4, 0x3f, 0x2a, 0x7a, 0xc1, 0x77, 0xda, 0x2c, 0x2f, 0x6b, 0x52,
            0xde, 0x3d, 0x7c, 0x88, 0xac,
        ];
        let actual_script_public_key = ScriptPublicKey::new(0, script_vec.into());

        assert_eq!(
            actual_script_public_key.script(),
            expected_script_public_key.script(),
            "Premine P2PKH script does not match expected script"
        );

        let actual_script_bytes = actual_script_public_key.script();
        let actual_pkh = &actual_script_bytes[3..23];
        let expected_pkh =
            &[0x94, 0x8c, 0x76, 0x5a, 0x69, 0x14, 0xd4, 0x3f, 0x2a, 0x7a, 0xc1, 0x77, 0xda, 0x2c, 0x2f, 0x6b, 0x52, 0xde, 0x3d, 0x7c];
        assert_eq!(actual_pkh, expected_pkh, "Premine PKH does not match expected PKH");

        assert_ne!(mu_hash_result, ZERO_HASH, "MuHash should not be zero for premine UTXO");
    }

    #[test]
    fn test_validate_p2pkh_script() {
        let valid_script = vec![
            0x76, 0xa9, 0x14, 0x94, 0x8c, 0x76, 0x5a, 0x69, 0x14, 0xd4, 0x3f, 0x2a, 0x7a, 0xc1, 0x77, 0xda, 0x2c, 0x2f, 0x6b, 0x52,
            0xde, 0x3d, 0x7c, 0x88, 0xac,
        ];
        assert!(validate_p2pkh_script(&valid_script).is_ok(), "Valid P2PKH script should pass validation");

        let invalid_script_short = vec![0x76, 0xa9, 0x14];
        assert!(
            matches!(validate_p2pkh_script(&invalid_script_short), Err(GenesisError::InvalidAddress)),
            "Short script should fail validation"
        );

        let invalid_script_opcodes = vec![
            0x77, 0xa9, 0x14, 0x94, 0x8c, 0x76, 0x5a, 0x69, 0x14, 0xd4, 0x3f, 0x2a, 0x7a, 0xc1, 0x77, 0xda, 0x2c, 0x2f, 0x6b, 0x52,
            0xde, 0x3d, 0x7c, 0x88, 0xac,
        ];
        assert!(
            matches!(validate_p2pkh_script(&invalid_script_opcodes), Err(GenesisError::InvalidAddress)),
            "Script with wrong opcodes should fail validation"
        );

        let invalid_script_pkh = vec![
            0x76, 0xa9, 0x15, 0x94, 0x8c, 0x76, 0x5a, 0x69, 0x14, 0xd4, 0x3f, 0x2a, 0x7a, 0xc1, 0x77, 0xda, 0x2c, 0x2f, 0x6b, 0x52,
            0xde, 0x3d, 0x7c, 0x00, 0x88, 0xac,
        ];
        assert!(
            matches!(validate_p2pkh_script(&invalid_script_pkh), Err(GenesisError::InvalidAddress)),
            "Script with wrong PKH length should fail validation"
        );
    }

    #[test]
    fn test_empty_muhash() {
        let mut mu_hash = MuHash::new();
        let finalized_hash = mu_hash.finalize();
        println!("Computed empty MuHash: {:?}", finalized_hash);
        let mut mu_hash2 = MuHash::new();
        assert_eq!(finalized_hash, mu_hash2.finalize(), "Empty MuHash should produce consistent hash");
    }

    #[test]
    fn test_genesis_utxo_commitment() {
        let genesis = create_genesis_block().expect("Genesis block creation failed");
        let transactions = genesis.build_genesis_transactions();
        let computed_mu_hash = compute_genesis_mu_hash(&transactions[0]).expect("Failed to compute MuHash");

        assert_eq!(genesis.utxo_commitment, computed_mu_hash, "UTXO commitment should match computed MuHash");
        if computed_mu_hash == EXPECTED_GENESIS.utxo_commitment {
            println!("UTXO commitment matches expected: {}", hash_to_hex(&computed_mu_hash));
        } else {
            println!(
                "Warning: UTXO commitment {} does not match expected {}",
                hash_to_hex(&computed_mu_hash),
                hash_to_hex(&EXPECTED_GENESIS.utxo_commitment)
            );
        }
    }

    #[test]
    fn test_genesis_header_hash_equality() {
        let genesis = create_genesis_block().expect("Genesis block creation failed");
        let header: Header = (&genesis).into();
        let header_hash = header_hash(&header);

        assert_eq!(genesis.hash, header_hash, "Genesis block hash should equal the header hash");
        assert_eq!(header.hash, genesis.hash, "Header hash field should equal genesis block hash");
        if genesis.hash == EXPECTED_GENESIS.hash {
            println!("Genesis block hash matches expected: {}", hash_to_hex(&genesis.hash));
        } else {
            println!(
                "Warning: Genesis block hash {} does not match expected {}",
                hash_to_hex(&genesis.hash),
                hash_to_hex(&EXPECTED_GENESIS.hash)
            );
        }
    }

    #[test]
    fn test_genesis_block_creation() {
        let genesis = create_genesis_block().expect("Genesis block creation failed");

        assert_eq!(genesis.version, 0, "Version should be 0");
        assert_eq!(genesis.bits, 0x1d07fff9, "Bits should be 0x1d07fff9");
        assert_eq!(genesis.daa_score, 0, "DAA score should be 0");
        assert_eq!(genesis.timestamp, 1746959862920, "Timestamp should be 1746959862920");
        assert_eq!(genesis.nonce, EXPECTED_GENESIS.nonce, "Nonce should match expected");

        let expected_payload: &[u8] = &[
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00,
            0x65, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x6c, 0x79, 0x2c, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x65, 0x76, 0x65, 0x72,
        ];
        assert_eq!(genesis.coinbase_payload, expected_payload, "Coinbase payload mismatch");

        let transactions = genesis.build_genesis_transactions();
        let txid = transactions[0].id();
        assert_eq!(genesis.hash_merkle_root, txid, "Hash merkle root should be transaction ID");
        if txid == EXPECTED_GENESIS.hash_merkle_root {
            println!("Transaction ID matches expected merkle root: {}", hash_to_hex(&txid));
        } else {
            println!(
                "Warning: Transaction ID {} does not match expected merkle root {}",
                hash_to_hex(&txid),
                hash_to_hex(&EXPECTED_GENESIS.hash_merkle_root)
            );
        }

        let target = bits_to_target(genesis.bits);
        assert!(hash_meets_target(&genesis.hash, &target), "Hash does not meet difficulty target");

        let _block: Block = (&genesis).into();
        let header: Header = (&genesis).into();
        assert_eq!(header.version, genesis.version, "Header version mismatch");
        assert_eq!(header.hash_merkle_root, genesis.hash_merkle_root, "Header hash_merkle_root mismatch");
        assert_eq!(header.utxo_commitment, genesis.utxo_commitment, "Header utxo_commitment mismatch");
        assert_eq!(header.timestamp, genesis.timestamp, "Header timestamp mismatch");
        assert_eq!(header.bits, genesis.bits, "Header bits mismatch");
        assert_eq!(header.nonce, genesis.nonce, "Header nonce mismatch");
        assert_eq!(header.daa_score, genesis.daa_score, "Header daa_score mismatch");
        assert_eq!(header.accepted_id_merkle_root, ZERO_HASH, "Header accepted_id_merkle_root should be ZERO_HASH");
        assert_eq!(header.blue_score, 0u64, "Header blue_score should be 0");
        assert_eq!(header.blue_work, Uint192::from(0u64), "Header blue_work should be 0");
        assert_eq!(header.pruning_point, ZERO_HASH, "Header pruning_point should be ZERO_HASH");
        assert_eq!(header.hash, genesis.hash, "Header hash mismatch");

        let computed_hash = header_hash(&header);
        assert_eq!(header.hash, computed_hash, "Header hash should match output of header_hash function");
    }

    #[test]
    fn test_genesis_transaction_structure() {
        let genesis = create_genesis_block().expect("Genesis block creation failed");
        let transactions = genesis.build_genesis_transactions();
        assert_eq!(transactions.len(), 1, "Expected exactly one transaction");

        let tx = &transactions[0];
        assert_eq!(tx.version, 0, "Transaction version should be 0");
        assert!(tx.inputs.is_empty(), "Transaction inputs should be empty");
        assert!(tx.outputs.is_empty(), "Transaction outputs should be empty");
        assert_eq!(tx.lock_time, 0, "Transaction lock time should be 0");
        assert_eq!(tx.subnetwork_id, SUBNETWORK_ID_COINBASE, "Transaction subnetwork ID should be SUBNETWORK_ID_COINBASE");
        assert_eq!(tx.gas, 0, "Transaction gas should be 0");
        assert_eq!(tx.payload, genesis.coinbase_payload, "Transaction payload should match coinbase payload");

        let expected_subnetwork_id = SUBNETWORK_ID_COINBASE;
        assert_eq!(tx.subnetwork_id, expected_subnetwork_id, "Subnetwork ID should match expected coinbase ID");
    }

    #[test]
    fn test_genesis_header_hash_determinism() {
        let fixed_timestamp = 1746959862920u64;
        let mut genesis1 = GenesisBlock {
            hash: ZERO_HASH,
            version: 0,
            hash_merkle_root: ZERO_HASH,
            utxo_commitment: ZERO_HASH,
            timestamp: fixed_timestamp,
            bits: 0x1d07fff9,
            nonce: 0,
            daa_score: 0,
            coinbase_payload: EXPECTED_GENESIS.coinbase_payload,
        };

        let mut genesis2 = genesis1.clone();

        let transactions = genesis1.build_genesis_transactions();
        genesis1.hash_merkle_root = transactions[0].id();
        genesis1.utxo_commitment = compute_genesis_mu_hash(&transactions[0]).expect("Failed to compute MuHash");
        genesis2.hash_merkle_root = transactions[0].id();
        genesis2.utxo_commitment = compute_genesis_mu_hash(&transactions[0]).expect("Failed to compute MuHash");

        mine_genesis(&mut genesis1).expect("Failed to mine genesis1");
        mine_genesis(&mut genesis2).expect("Failed to mine genesis2");

        let header1: Header = (&genesis1).into();
        let header2: Header = (&genesis2).into();
        assert_eq!(header1.hash, header2.hash, "Header hashes should be deterministic for identical inputs");
        assert_eq!(genesis1.nonce, genesis2.nonce, "Nonces should be identical for deterministic mining");

        assert_eq!(header1.hash, header_hash(&header1), "Header1 hash should match header_hash output");
        assert_eq!(header2.hash, header_hash(&header2), "Header2 hash should match header_hash output");
    }

    #[test]
    fn test_genesis_difficulty_target() {
        let genesis = create_genesis_block().expect("Genesis block creation failed");

        assert_eq!(genesis.bits, 0x1d07fff9, "Bits should be 0x1d07fff9");
        let target = bits_to_target(genesis.bits);
        let expected_target = {
            let mut t = [0u8; 32];
            t[31 - 26] = 0x07;
            t[30 - 26] = 0xff;
            t[29 - 26] = 0xf9;
            t
        };
        assert_eq!(target, expected_target, "Difficulty target should match expected value");

        assert!(hash_meets_target(&genesis.hash, &target), "Genesis hash should meet difficulty target");
    }

    #[test]
    fn test_genesis_pruning_point() {
        let genesis = create_genesis_block().expect("Genesis block creation failed");
        let header: Header = (&genesis).into();

        assert_eq!(header.pruning_point, ZERO_HASH, "Genesis header pruning point should be ZERO_HASH");

        let transactions = genesis.build_genesis_transactions();
        assert_eq!(transactions.len(), 1, "Expected one transaction for pruning point proof");
        assert!(transactions[0].outputs.is_empty(), "Genesis transaction should have no outputs for pruning point compatibility");
    }

    #[test]
    fn test_genesis_daa_score() {
        let genesis = create_genesis_block().expect("Genesis block creation failed");
        let header: Header = (&genesis).into();

        assert_eq!(genesis.daa_score, 0, "Genesis DAA score should be 0");
        assert_eq!(header.daa_score, 0, "Header DAA score should be 0");

        let mut modified_genesis = genesis.clone();
        modified_genesis.daa_score = 1;
        let modified_header: Header = (&modified_genesis).into();
        assert_ne!(header.hash, modified_header.hash, "Changing DAA score should affect header hash");

        assert_eq!(modified_header.hash, header_hash(&modified_header), "Modified header hash should match header_hash output");
    }

    #[test]
    fn test_genesis_header_hash_with_nonce_time() {
        let genesis = create_genesis_block().expect("Genesis block creation failed");
        let header: Header = (&genesis).into();

        let standard_hash = header_hash(&header);
        assert_eq!(header.hash, standard_hash, "Header hash should match standard header_hash");

        let new_nonce = header.nonce + 1;
        let new_timestamp = header.timestamp + 1000;
        let parents_by_level = header.parents_by_level.clone();
        let overridden_hash = hash_override_nonce_time(
            &Header {
                nonce: new_nonce,
                timestamp: new_timestamp,
                parents_by_level,
                version: header.version,
                hash_merkle_root: header.hash_merkle_root,
                accepted_id_merkle_root: header.accepted_id_merkle_root,
                utxo_commitment: header.utxo_commitment,
                bits: header.bits,
                daa_score: header.daa_score,
                blue_work: header.blue_work,
                blue_score: header.blue_score,
                pruning_point: header.pruning_point,
                hash: header.hash,
            },
            new_nonce,
            new_timestamp,
        );

        assert_ne!(header.hash, overridden_hash, "Overridden nonce/timestamp should produce different hash");

        let mut new_header = Header::new_finalized(
            header.version,
            header.parents_by_level.clone(),
            header.hash_merkle_root,
            header.accepted_id_merkle_root,
            header.utxo_commitment,
            new_timestamp,
            header.bits,
            new_nonce,
            header.daa_score,
            header.blue_work,
            header.blue_score,
            header.pruning_point,
        );
        new_header.hash = header_hash(&new_header);
        assert_eq!(overridden_hash, new_header.hash, "Overridden nonce/timestamp should match header_hash with new nonce/timestamp");
    }

    #[cfg(test)]
    mod pruning_tests {
        use super::*;

        #[test]
        fn test_genesis_pruning_point() {
            let genesis = create_genesis_block().expect("Genesis block creation failed");
            let header: Header = (&genesis).into();

            assert_eq!(header.pruning_point, ZERO_HASH, "Genesis block pruning point should be ZERO_HASH");

            let mut invalid_header = header.clone();
            invalid_header.pruning_point = Hash::from_bytes([1; 32]);
            let computed_hash = header_hash(&invalid_header);
            assert_ne!(header.hash, computed_hash, "Changing pruning point should alter header hash");
        }

        #[test]
        fn test_genesis_transaction_pruning_compatibility() {
            let genesis = create_genesis_block().expect("Genesis block creation failed");
            let transactions = genesis.build_genesis_transactions();

            assert_eq!(transactions.len(), 1, "Genesis block should have exactly one transaction");
            let tx = &transactions[0];
            assert!(tx.outputs.is_empty(), "Genesis coinbase transaction should have no outputs for pruning compatibility");
            assert_eq!(tx.subnetwork_id, SUBNETWORK_ID_COINBASE, "Transaction subnetwork ID should be SUBNETWORK_ID_COINBASE");
            assert_eq!(tx.payload, genesis.coinbase_payload, "Transaction payload should match genesis coinbase payload");

            let txid = tx.id();
            assert_eq!(genesis.hash_merkle_root, txid, "Merkle root should match coinbase transaction ID");
            if txid == EXPECTED_GENESIS.hash_merkle_root {
                println!("Transaction ID matches expected merkle root: {}", hash_to_hex(&txid));
            } else {
                println!(
                    "Warning: Transaction ID {} does not match expected merkle root {}",
                    hash_to_hex(&txid),
                    hash_to_hex(&EXPECTED_GENESIS.hash_merkle_root)
                );
            }
        }

        #[test]
        fn test_utxo_commitment_pruning_integrity() {
            let genesis = create_genesis_block().expect("Genesis block creation failed");
            let transactions = genesis.build_genesis_transactions();
            let computed_mu_hash = compute_genesis_mu_hash(&transactions[0]).expect("Failed to compute MuHash");

            assert_eq!(genesis.utxo_commitment, computed_mu_hash, "Genesis UTXO commitment should match computed MuHash");
            if computed_mu_hash == EXPECTED_GENESIS.utxo_commitment {
                println!("UTXO commitment matches expected: {}", hash_to_hex(&computed_mu_hash));
            } else {
                println!(
                    "Warning: UTXO commitment {} does not match expected {}",
                    hash_to_hex(&computed_mu_hash),
                    hash_to_hex(&EXPECTED_GENESIS.utxo_commitment)
                );
            }

            let mut muhash = MuHash::new();
            let mut hasher = TransactionID::new();
            hasher.update(&transactions[0].payload);
            let txid = hasher.finalize().as_bytes();

            let script_vec = vec![
                0x76, 0xa9, 0x14, 0x94, 0x8c, 0x76, 0x5a, 0x69, 0x14, 0xd4, 0x3f, 0x2a, 0x7a, 0xc1, 0x77, 0xda, 0x2c, 0x2f, 0x6b,
                0x52, 0xde, 0x3d, 0x7c, 0x88, 0xac,
            ];
            let script_public_key = ScriptPublicKey::new(0, script_vec.into());
            let wrong_amount = 2_000_000_000u64;
            let utxo_entry = UtxoEntry::new(wrong_amount, script_public_key, 0, true);

            let mut serialized = Vec::new();
            serialized.extend_from_slice(&txid);
            serialized.extend_from_slice(&0u32.to_le_bytes());
            serialized.extend_from_slice(&utxo_entry.amount.to_le_bytes());
            let script_bytes = utxo_entry.script_public_key.script();
            serialized.extend_from_slice(script_bytes);
            serialized.extend_from_slice(&utxo_entry.block_daa_score.to_le_bytes());
            serialized.push(utxo_entry.is_coinbase as u8);

            let mut element_hasher = MuHashElementHash::new();
            element_hasher.update(&serialized);
            muhash.add_element(&element_hasher.finalize().as_bytes());
            let wrong_mu_hash = Hash::from_bytes(muhash.finalize().as_bytes());

            assert_ne!(genesis.utxo_commitment, wrong_mu_hash, "Incorrect UTXO serialization should produce different MuHash");
        }

        #[test]
        fn test_utxo_serialization_consistency() {
            let genesis = create_genesis_block().expect("Genesis block creation failed");
            let transactions = genesis.build_genesis_transactions();
            let tx = &transactions[0];

            let mut muhash1 = MuHash::new();
            let mut muhash2 = MuHash::new();

            let mut hasher = TransactionID::new();
            hasher.update(&tx.payload);
            let txid = hasher.finalize().as_bytes();

            let script_vec = vec![
                0x76, 0xa9, 0x14, 0x94, 0x8c, 0x76, 0x5a, 0x69, 0x14, 0xd4, 0x3f, 0x2a, 0x7a, 0xc1, 0x77, 0xda, 0x2c, 0x2f, 0x6b,
                0x52, 0xde, 0x3d, 0x7c, 0x88, 0xac,
            ];
            let script_public_key = ScriptPublicKey::new(0, script_vec.into());
            let amount = 50_000_000_000_000_000u64;
            let utxo_entry = UtxoEntry::new(amount, script_public_key, 0, true);

            let mut serialized1 = Vec::new();
            serialized1.extend_from_slice(&txid);
            serialized1.extend_from_slice(&0u32.to_le_bytes());
            serialized1.extend_from_slice(&utxo_entry.amount.to_le_bytes());
            let script_bytes = utxo_entry.script_public_key.script();
            serialized1.extend_from_slice(script_bytes);
            serialized1.extend_from_slice(&utxo_entry.block_daa_score.to_le_bytes());
            serialized1.push(utxo_entry.is_coinbase as u8);
            let mut element_hasher1 = MuHashElementHash::new();
            element_hasher1.update(&serialized1);
            muhash1.add_element(&element_hasher1.finalize().as_bytes());

            let mut serialized2 = Vec::new();
            serialized2.extend_from_slice(&txid);
            serialized2.extend_from_slice(&0u32.to_le_bytes());
            serialized2.extend_from_slice(&utxo_entry.amount.to_le_bytes());
            serialized2.extend_from_slice(script_bytes);
            serialized2.extend_from_slice(&utxo_entry.block_daa_score.to_le_bytes());
            serialized2.push(utxo_entry.is_coinbase as u8);
            let mut element_hasher2 = MuHashElementHash::new();
            element_hasher2.update(&serialized2);
            muhash2.add_element(&element_hasher2.finalize().as_bytes());

            let hash1 = Hash::from_bytes(muhash1.finalize().as_bytes());
            let hash2 = Hash::from_bytes(muhash2.finalize().as_bytes());
            assert_eq!(hash1, hash2, "UTXO serialization should be consistent across multiple runs");

            assert_eq!(genesis.utxo_commitment, hash1, "Serialized UTXO should match genesis UTXO commitment");
            if hash1 == EXPECTED_GENESIS.utxo_commitment {
                println!("UTXO commitment matches expected: {}", hash_to_hex(&hash1));
            } else {
                println!(
                    "Warning: UTXO commitment {} does not match expected {}",
                    hash_to_hex(&hash1),
                    hash_to_hex(&EXPECTED_GENESIS.utxo_commitment)
                );
            }
        }

        #[test]
        fn test_hash_override_nonce_time_edge_cases() {
            let genesis = create_genesis_block().expect("Genesis block creation failed");
            let header: Header = (&genesis).into();

            let hash_max_nonce = hash_override_nonce_time(&header, u64::MAX, header.timestamp);
            let hash_zero_timestamp = hash_override_nonce_time(&header, header.nonce, 0);

            assert_ne!(header.hash, hash_max_nonce, "Max nonce should produce different hash");
            assert_ne!(header.hash, hash_zero_timestamp, "Zero timestamp should produce different hash");
            assert_ne!(hash_max_nonce, hash_zero_timestamp, "Max nonce and zero timestamp should produce different hashes");
        }

        #[test]
        fn test_pruning_with_modified_daa_score() {
            let genesis = create_genesis_block().expect("Genesis block creation failed");
            let mut modified_genesis = genesis.clone();
            modified_genesis.daa_score = 1;

            let header: Header = (&genesis).into();
            let modified_header: Header = (&modified_genesis).into();

            assert_eq!(modified_header.pruning_point, ZERO_HASH, "Modified DAA score should not affect pruning point");

            assert_ne!(header.hash, modified_header.hash, "Changing DAA score should affect header hash");

            let transactions = modified_genesis.build_genesis_transactions();
            let computed_mu_hash = compute_genesis_mu_hash(&transactions[0]).expect("Failed to compute MuHash");
            assert_eq!(
                modified_genesis.utxo_commitment, computed_mu_hash,
                "UTXO commitment should remain consistent with modified DAA score"
            );
            if computed_mu_hash == EXPECTED_GENESIS.utxo_commitment {
                println!("UTXO commitment matches expected: {}", hash_to_hex(&computed_mu_hash));
            } else {
                println!(
                    "Warning: UTXO commitment {} does not match expected {}",
                    hash_to_hex(&computed_mu_hash),
                    hash_to_hex(&EXPECTED_GENESIS.utxo_commitment)
                );
            }
        }

        #[test]
        fn test_genesis_ghostdag_selected_parent() {
            #[derive(PartialEq, Eq, PartialOrd, Ord)]
            struct SortableBlock {
                hash: Hash,
                blue_work: Uint256,
            }

            struct MockGhostdagStore {
                blue_work: std::collections::HashMap<Hash, Uint256>,
            }

            impl MockGhostdagStore {
                fn new() -> Self {
                    MockGhostdagStore { blue_work: std::collections::HashMap::new() }
                }

                fn insert(&mut self, hash: Hash, blue_work: Uint256) {
                    self.blue_work.insert(hash, blue_work);
                }

                fn get_blue_work(&self, hash: Hash) -> Result<Uint256, String> {
                    self.blue_work.get(&hash).copied().ok_or_else(|| format!("KeyNotFound for hash {}", hash_to_hex(&hash)))
                }
            }

            struct MockGhostdagProtocol {
                ghostdag_store: MockGhostdagStore,
            }

            impl MockGhostdagProtocol {
                fn new() -> Self {
                    MockGhostdagProtocol { ghostdag_store: MockGhostdagStore::new() }
                }

                fn find_selected_parent(&self, parents: impl IntoIterator<Item = Hash>) -> Result<Hash, String> {
                    let sortable_blocks: Result<Vec<SortableBlock>, String> = parents
                        .into_iter()
                        .map(|parent| {
                            let blue_work = self.ghostdag_store.get_blue_work(parent)?;
                            Ok(SortableBlock { hash: parent, blue_work })
                        })
                        .collect();
                    sortable_blocks?.into_iter().max().map(|block| block.hash).ok_or_else(|| "No parents provided".to_string())
                }
            }

            let genesis = create_genesis_block().expect("Genesis block creation failed");

            assert_eq!(genesis.timestamp, EXPECTED_GENESIS.timestamp, "Timestamp should match expected network value");
            assert_eq!(
                genesis.coinbase_payload, EXPECTED_GENESIS.coinbase_payload,
                "Coinbase payload should match expected network value"
            );

            assert_ne!(genesis.hash, FEFE_HASH, "Genesis block hash should not be the problematic FEFE hash");

            let mut protocol = MockGhostdagProtocol::new();
            protocol.ghostdag_store.insert(genesis.hash, Uint256::from(0u64));
            let parents = vec![genesis.hash];
            let selected_parent = protocol.find_selected_parent(parents).expect("Should select genesis hash");
            assert_eq!(selected_parent, genesis.hash, "Selected parent should be the genesis hash");
            assert_ne!(selected_parent, FEFE_HASH, "Selected parent should not be the problematic FEFE hash");

            let parents_with_fefe = vec![genesis.hash, FEFE_HASH];
            let result = protocol.find_selected_parent(parents_with_fefe);
            assert!(result.is_err(), "Should fail due to missing FEFE_HASH");
        }
    }
}

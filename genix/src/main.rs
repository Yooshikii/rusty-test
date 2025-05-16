use thiserror::Error;
use kaspa_consensus_core::block::Block;
use kaspa_consensus_core::hashing::header::hash as header_hash;
use kaspa_consensus_core::hashing::HasherExtensions;
use kaspa_consensus_core::header::Header;
use kaspa_consensus_core::subnets::SUBNETWORK_ID_COINBASE;
use kaspa_consensus_core::tx::Transaction;
use kaspa_hashes::{BlockHash, Hash, HasherBase, ZERO_HASH};
use kaspa_muhash::MuHash;

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
        .update(timestamp.to_le_bytes())
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
            0,
            Vec::new(),
            Vec::new(),
            0,
            SUBNETWORK_ID_COINBASE,
            0,
            self.coinbase_payload.to_vec(),
        );
        vec![coinbase_tx]
    }
}

impl From<&GenesisBlock> for Header {
    fn from(genesis: &GenesisBlock) -> Self {
        let mut header = Header::new_finalized(
            genesis.version,
            Vec::new(), // No parents for genesis
            genesis.hash_merkle_root,
            ZERO_HASH,
            genesis.utxo_commitment,
            genesis.timestamp,
            genesis.bits,
            genesis.nonce,
            genesis.daa_score,
            0.into(), // blue_work
            0,        // blue_score
            ZERO_HASH,
        );
        header.finalize();
        header
    }
}

impl From<&GenesisBlock> for Block {
    fn from(genesis: &GenesisBlock) -> Self {
        Block::new(genesis.into(), genesis.build_genesis_transactions())
    }
}

fn compute_genesis_mu_hash(_tx: &Transaction) -> Result<Hash, GenesisError> {
    let mut muhash = MuHash::new();
    Ok(muhash.finalize())
}

fn create_genesis_block() -> Result<GenesisBlock, GenesisError> {
    const COINBASE_PAYLOAD: &[u8] = &[
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0xe1, 0xf5, 0x05, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00,
        0x01,
        0x00,
        0x65, 0x74, 0x65, 0x72, 0x6e, 0x61, 0x6c, 0x6c, 0x79, 0x2c, 0x20, 0x66, 0x6f, 0x72, 0x20, 0x65, 0x76, 0x65,
        0x72,
    ];

    let mut genesis = GenesisBlock {
        hash: ZERO_HASH,
        version: 0,
        hash_merkle_root: ZERO_HASH,
        utxo_commitment: ZERO_HASH,
        timestamp: 1715896800,
        bits: 0x1e007fff,
        nonce: 0,
        daa_score: 0,
        coinbase_payload: COINBASE_PAYLOAD,
    };

    // Compute transaction data
    let transactions = genesis.build_genesis_transactions();
    genesis.hash_merkle_root = transactions[0].id();
    genesis.utxo_commitment = compute_genesis_mu_hash(&transactions[0])?;

    // Mine the genesis block to find a valid nonce
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
            new_header.finalize();
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

            // Print GENESIS
            println!("pub const GENESIS: GenesisBlock = GenesisBlock {{");

            print!("    hash: Hash::from_bytes([");
            for (i, byte) in genesis.hash.as_bytes().iter().enumerate() {
                if i % 8 == 0 { print!("\n        "); }
                print!("0x{:02x}, ", byte);
            }
            println!("\n    ]),");

            println!("    version: {},", genesis.version);

            print!("    hash_merkle_root: Hash::from_bytes([");
            for (i, byte) in genesis.hash_merkle_root.as_bytes().iter().enumerate() {
                if i % 8 == 0 { print!("\n        "); }
                print!("0x{:02x}, ", byte);
            }
            println!("\n    ]),");

            print!("    utxo_commitment: Hash::from_bytes([");
            for (i, byte) in genesis.utxo_commitment.as_bytes().iter().enumerate() {
                if i % 8 == 0 { print!("\n        "); }
                print!("0x{:02x}, ", byte);
            }
            println!("\n    ]),");

            println!("    timestamp: 0x{:x},", genesis.timestamp);
            println!("    bits: 0x{:08x},", genesis.bits);
            println!("    nonce: 0x{:08x},", genesis.nonce);
            println!("    daa_score: {},", genesis.daa_score);

            println!("    #[rustfmt::skip]");
            print!("    coinbase_payload: &[");
            for (i, byte) in genesis.coinbase_payload.iter().enumerate() {
                if i % 8 == 0 { print!("\n        "); }
                print!("0x{:02x}, ", byte);
            }
            let message = String::from_utf8_lossy(&genesis.coinbase_payload[20..]);
            println!("\n    ], // {}", message);
            println!("}};\n");

            // Print GENESIS_HEADER
            println!("pub const GENESIS_HEADER: Header = Header {{");

            print!("    hash: Hash::from_bytes([");
            for (i, byte) in header.hash.as_bytes().iter().enumerate() {
                if i % 8 == 0 { print!("\n        "); }
                print!("0x{:02x}, ", byte);
            }
            println!("\n    ]),");

            println!("    version: {},", header.version);
            println!("    parents_by_level: Vec::new(),");

            print!("    hash_merkle_root: Hash::from_bytes([");
            for (i, byte) in header.hash_merkle_root.as_bytes().iter().enumerate() {
                if i % 8 == 0 { print!("\n        "); }
                print!("0x{:02x}, ", byte);
            }
            println!("\n    ]),");

            print!("    accepted_id_merkle_root: Hash::from_bytes([");
            for (i, byte) in header.accepted_id_merkle_root.as_bytes().iter().enumerate() {
                if i % 8 == 0 { print!("\n        "); }
                print!("0x{:02x}, ", byte);
            }
            println!("\n    ]),");

            print!("    utxo_commitment: Hash::from_bytes([");
            for (i, byte) in header.utxo_commitment.as_bytes().iter().enumerate() {
                if i % 8 == 0 { print!("\n        "); }
                print!("0x{:02x}, ", byte);
            }
            println!("\n    ]),");

            println!("    timestamp: 0x{:x},", header.timestamp);
            println!("    bits: 0x{:08x},", header.bits);
            println!("    nonce: 0x{:08x},", header.nonce);
            println!("    daa_score: {},", header.daa_score);
            println!("    blue_score: {},", header.blue_score);
            println!("    blue_work: {},", header.blue_work);

            print!("    pruning_point: Hash::from_bytes([");
            for (i, byte) in header.pruning_point.as_bytes().iter().enumerate() {
                if i % 8 == 0 { print!("\n        "); }
                print!("0x{:02x}, ", byte);
            }
            println!("\n    ]),");

            println!("}};");
        }
        Err(e) => {
            eprintln!("Error creating genesis block: {}", e);
        }
    }
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_empty_hash() {
        let mut empty = MuHash::new();
        let computed_hash = empty.finalize();
        let expected_hash = Hash::from_bytes([
            0x6f, 0x2c, 0x2e, 0x18, 0xaf, 0x95, 0x1c, 0x73, 0x80, 0xaf, 0xde, 0xc8, 0x00, 0xac, 0x60, 0x9e,
            0xdb, 0xa3, 0xea, 0xba, 0x0d, 0xc7, 0x1e, 0x86, 0x80, 0x56, 0xba, 0xae, 0x3e, 0x24, 0x4a, 0x70,
        ]);
        assert_eq!(computed_hash, expected_hash, "Empty MuHash does not match expected blake3 hash");
    }

    #[test]
    fn test_genesis_block_creation() {
        println!("Running test_genesis_block_creation...");

        match create_genesis_block() {
            Ok(genesis) => {
                let header: Header = (&genesis).into();
                let target = bits_to_target(genesis.bits);

                // Test 1: Verify the genesis block hash meets the target difficulty
                let hash_valid = hash_meets_target(&genesis.hash, &target);
                println!("Test 1 - Genesis Hash Meets Target Difficulty: {}", hash_valid);
                println!("Computed Hash: {:?}", genesis.hash);
                println!("Target: {:?}", target);

                // Test 2: Verify no parents
                let no_parents = header.parents_by_level.is_empty();
                println!("Test 2 - No Parents (parents_by_level empty): {}", no_parents);
                println!("Parents by Level: {:?}", header.parents_by_level);

                // Test 3: Verify header hash matches genesis hash
                let header_hash_correct = header.hash == genesis.hash;
                println!("Test 3 - Header Hash Matches Genesis Hash: {}", header_hash_correct);
                println!("Header Hash: {:?}", header.hash);
                println!("Genesis Hash: {:?}", genesis.hash);

                // Test 4: Verify utxo_commitment
                let expected_utxo_commitment = MuHash::new().finalize();
                let utxo_commitment_valid = genesis.utxo_commitment == expected_utxo_commitment;
                println!("Test 4 - UTXO Commitment Valid: {}", utxo_commitment_valid);
                println!("UTXO Commitment: {:?}", genesis.utxo_commitment);
                println!("Expected UTXO Commitment: {:?}", expected_utxo_commitment);

                // Assert all conditions
                assert!(hash_valid, "Genesis hash does not meet target difficulty");
                assert!(no_parents, "Genesis block should have no parents");
                assert!(header_hash_correct, "Header hash does not match genesis hash");
                assert!(utxo_commitment_valid, "UTXO commitment is invalid");

                println!("All tests passed!");
            }
            Err(e) => {
                println!("Test failed: Error creating genesis block: {}", e);
                panic!("Genesis block creation failed");
            }
        }
    }
}
extern crate flame;
extern crate glob;
use glob::glob;
#[macro_use]
extern crate flamer;
use std::collections::HashMap;
use std::fs::File;
use std::process::Command;
use std::vec;
mod macros;

use ark_ec::twisted_edwards_extended::GroupProjective;
use bandersnatch::BandersnatchParameters;
use verkle_trie::committer::precompute::PrecomputeLagrange;
use verkle_trie::database::memory_db::MemoryDb;
use verkle_trie::proof::VerkleProof;
use verkle_trie::{Config, Trie, TrieTrait, VerkleConfig};

#[flame]
fn get_verkle_conf(db: MemoryDb) -> Config<MemoryDb, PrecomputeLagrange> {
    let result = track!("config open from file", VerkleConfig::open(db.clone()));
    if result.is_err() {
        return track!("config new compute", VerkleConfig::new(db)).unwrap();
    }
    result.unwrap()
}

#[flame("config_gen")]
fn inmem_trie_new() -> Trie<MemoryDb, PrecomputeLagrange> {
    let db = MemoryDb::new();
    let cfg = track!("config generation", get_verkle_conf(db));
    let trie = Trie::new(cfg);
    trie
}

fn shutdown() {
    flame::dump_html(&mut File::create("flamegraph.html").unwrap()).unwrap();
    // Compile steplogs to png
    for e in glob("./*.dot").expect("Failed to read glob pattern") {
        Command::new("dot")
            .arg("-Tpng")
            .arg(e.unwrap().as_os_str())
            .arg("-O")
            .spawn()
            .expect("");
    }
}

fn new_block_kvs() -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
    (
        vec![
            makeu8_32!("02"),
            makeu8_32!("02002dc7f11494ffb7e3a672badcdad1bb77f23f3a066b2c95942a23b2c9130b"),
            makeu8_32!("02002dc7f11494ffb7e3a672badcdad1bb77f23f3a066b2c95942a23b2c913ae"),
            makeu8_32!("03"),
        ],
        vec![
            makeu8_32!("77"),
            makeu8_32!("a04"),
            makeu8_32!("89"),
            makeu8_32!("1010f"),
        ],
    )
}

fn new_block_proofkvs() -> (Vec<[u8; 32]>, Vec<Option<[u8; 32]>>) {
    (
        vec![
            makeu8_32!("02002dc7f11494ffb7e3a672badcdad1bb77f23f3a066b2c95942a23b2c913ae"),
            makeu8_32!("03"),
            makeu8_32!("04"),
        ],
        vec![Some(makeu8_32!("89")), Some(makeu8_32!("1010f")), None],
    )
}

fn new_block_wrongkvs() -> (Vec<[u8; 32]>, Vec<[u8; 32]>) {
    (
        vec![makeu8_32!("02"), makeu8_32!("990")],
        vec![makeu8_32!("71"), makeu8_32!("89")],
    )
}

fn steplog_insert(
    mut trie: Trie<MemoryDb, PrecomputeLagrange>,
    keys: Vec<[u8; 32]>,
    vals: Vec<[u8; 32]>,
) -> Trie<MemoryDb, PrecomputeLagrange> {
    let len = keys.len();
    track!("root commitment compute", trie.root_commitment());
    track!("dot save", trie.storage.to_dot("steplog_pre.dot"));
    for i in 0..len {
        trie.insert_single(keys[i], vals[i]);
        track!("root commitment compute", trie.root_commitment());
        track!(
            "dot save",
            trie.storage.to_dot(format!("steplog_{}.dot", i).as_str())
        );
    }
    trie
}

#[derive(Clone)]
struct FullNode {
    state_trie: Trie<MemoryDb, PrecomputeLagrange>,
}

impl FullNode {
    fn new(keys: Vec<[u8; 32]>, values: Vec<[u8; 32]>, step_logging: bool) -> Self {
        let state_trie = track!("creating a state trie", inmem_trie_new());
        track!(
            "creating a full node",
            Self::create_node(state_trie, keys, values, step_logging)
        )
    }
    #[flame("create_node")]
    fn create_node(
        mut state_trie: Trie<MemoryDb, PrecomputeLagrange>,
        keys: Vec<[u8; 32]>,
        values: Vec<[u8; 32]>,
        step_logging: bool,
    ) -> Self {
        if !step_logging {
            track!(
                "insert full KV set into state trie",
                state_trie.insert(keys.into_iter().zip(values.into_iter()))
            );
        } else {
            state_trie = track!(
                "insert full KV set into state trie, step logging",
                steplog_insert(state_trie, keys, values)
            );
        }
        FullNode { state_trie }
    }

    #[flame("comm_root")]
    fn publish_commitment_root(&mut self) -> GroupProjective<BandersnatchParameters> {
        track!(
            "generating root commitment",
            self.state_trie.root_commitment()
        )
    }

    fn generate_proof(&mut self, keys: Vec<[u8; 32]>) -> VerkleProof {
        track!(
            "generating proof for select keys",
            self.state_trie.create_verkle_proof(keys.into_iter())
        )
    }
}

struct Verifier {}

impl Verifier {
    #[flame("verifier_prove")]
    fn prove(
        root: GroupProjective<BandersnatchParameters>,
        verkle_proof: VerkleProof,
        proof_keys: Vec<[u8; 32]>,
        proof_vals: Vec<Option<[u8; 32]>>,
    ) -> bool {
        // let proof_vals = proof_vals.into_iter().map(|x| Some(x)).collect();
        let (proof_result, _) = track!(
            "verifier: proof verification",
            verkle_proof.check(proof_keys, proof_vals, root)
        );
        proof_result
    }
}

fn run_simulation() {
    let (keys, values) = new_block_kvs();

    let mut miner = FullNode::new(keys, values, false);
    let mut prover = miner.clone();
    let bc_root_comm = miner.publish_commitment_root();

    let (proof_keys, proof_values) = new_block_proofkvs();
    let (wrong_keys, wrong_values) = new_block_wrongkvs();
    let verkle_proof = prover.generate_proof(proof_keys.clone());

    // Verifier
    assert!(Verifier::prove(bc_root_comm, verkle_proof.clone(), proof_keys, proof_values) == true);
    // assert!(Verifier::prove(bc_root_comm, verkle_proof, wrong_keys, wrong_values) == false); // Panics rn
}

fn run_simulation_with_images() {
    let (keys, values) = new_block_kvs();

    let mut miner = FullNode::new(keys, values, true);
    let mut prover = miner.clone();
    let bc_root_comm = miner.publish_commitment_root();

    let (proof_keys, proof_values) = new_block_proofkvs();
    let verkle_proof = prover.generate_proof(proof_keys.clone());

    // Verifier
    println!("Verkle Proof:\n{}", verkle_proof);
    // Multiproof
    assert!(
        Verifier::prove(
            bc_root_comm,
            verkle_proof.clone(),
            proof_keys.clone(),
            proof_values
        ) == true
    );

    shutdown();
}

#[flame("main")]
fn main() {
    // run_simulation();
    run_simulation_with_images();

    shutdown();
}

// Copyright (C) 2013-2020 Blockstack PBC, a public benefit corporation
// Copyright (C) 2020-2025 Stacks Open Internet Foundation
// Copyright (C) 2025 Jude Nelson
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc};
use std::time::{Duration, Instant};
use std::{env, thread};

use clarity::vm::types::{PrincipalData};
use stacks::chainstate::nakamoto::test_signers::TestSigners;
use stacks::chainstate::nakamoto::{NakamotoChainState};
use stacks::chainstate::stacks::db::StacksChainState;
use stacks_common::util::secp256k1::Secp256k1PrivateKey;

use super::bitcoin_regtest::BitcoinCoreController;
use crate::neon::{Counters};
use crate::run_loop::boot_nakamoto;
use crate::tests::neon_integrations::{
    get_chain_info_result,
    submit_tx,
    test_observer,
    wait_for_runloop,
};
use crate::tests::{
    make_contract_publish,
};
use crate::{tests, BitcoinRegtestController, BurnchainController};
use crate::tests::nakamoto_integrations::naka_neon_integration_conf;
use crate::tests::nakamoto_integrations::setup_stacker;
use crate::tests::nakamoto_integrations::boot_to_epoch_3;
use crate::tests::nakamoto_integrations::blind_signer;
use crate::tests::nakamoto_integrations::next_block_and;

pub const BNS_V2: &str = include_str!("./bnsv2/BNS-V2.clar");
pub const COMMISSION_TRAIT: &str = include_str!("./bnsv2/commission-trait.clar");
pub const NAMESPACE_AIRDROP: &str = include_str!("./bnsv2/namespace-airdrop.clar");
pub const SIP_009_TRAIT: &str = include_str!("./bnsv2/sip-09.clar");
pub const ZONEFILE_RESOLVER: &str = include_str!("./bnsv2/zonefile-resolver.clar");

/// Wait for a block commit, without producing a block
fn wait_for_first_naka_block_commit(timeout_secs: u64, naka_commits_submitted: &Arc<AtomicU64>) {
    let start = Instant::now();
    while naka_commits_submitted.load(Ordering::SeqCst) < 1 {
        if start.elapsed() > Duration::from_secs(timeout_secs) {
            error!("Timed out waiting for block commit");
            panic!();
        }
        thread::sleep(Duration::from_millis(100));
    }
}

#[test]
#[ignore]
pub fn wrb_playground() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    let http_port_str = env::var("WRB_PORT")
        .map(|s| s.to_string())
        .unwrap_or("30443".to_string());

    let http_port = http_port_str.parse::<u16>().unwrap();
    if http_port < 1024 {
        panic!("Invalid HTTP port");
    }

    let (mut naka_conf, _miner_account) = naka_neon_integration_conf(None);
    naka_conf.node.rpc_bind = format!("{}", http_port);

    let http_origin = format!("http://{}", &naka_conf.node.rpc_bind);
    naka_conf.miner.wait_on_interim_blocks = Duration::from_secs(1);
    let sender_sk = Secp256k1PrivateKey::from_hex("e89bb394ecd5161007a84b34ac98d4f7239016c91d3e0c7c3b97aa4996932883").unwrap();
    let sender_signer_sk = Secp256k1PrivateKey::new();
    let sender_signer_addr = tests::to_addr(&sender_signer_sk);
    let mut signers = TestSigners::new(vec![sender_signer_sk]);
    // setup sender + recipient for some test stx transfers
    // these are necessary for the interim blocks to get mined at all
    let sender_addr = tests::to_addr(&sender_sk);
    naka_conf.add_initial_balance(
        PrincipalData::from(sender_addr).to_string(),
        10000000
    );
    naka_conf.add_initial_balance(PrincipalData::from(sender_signer_addr).to_string(), 100000);
    let stacker_sk = setup_stacker(&mut naka_conf);

    test_observer::spawn();
    test_observer::register_any(&mut naka_conf);

    let mut btcd_controller = BitcoinCoreController::new(naka_conf.clone());
    btcd_controller
        .start_bitcoind()
        .expect("Failed starting bitcoind");
    let mut btc_regtest_controller = BitcoinRegtestController::new(naka_conf.clone(), None);
    btc_regtest_controller.bootstrap_chain(201);

    let mut run_loop = boot_nakamoto::BootRunLoop::new(naka_conf.clone()).unwrap();
    let run_loop_stopper = run_loop.get_termination_switch();
    let Counters {
        blocks_processed,
        naka_submitted_commits: commits_submitted,
        naka_proposed_blocks: proposals_submitted,
        ..
    } = run_loop.counters();

    let coord_channel = run_loop.coordinator_channels();

    let run_loop_thread = thread::Builder::new()
        .name("run_loop".into())
        .spawn(move || run_loop.start(None, 0))
        .unwrap();

    wait_for_runloop(&blocks_processed);
    boot_to_epoch_3(
        &naka_conf,
        &blocks_processed,
        &[stacker_sk],
        &[sender_signer_sk],
        &mut Some(&mut signers),
        &mut btc_regtest_controller,
    );

    info!("Bootstrapped to Epoch-3.0 boundary, starting nakamoto miner");

    let burnchain = naka_conf.get_burnchain();
    let sortdb = burnchain.open_sortition_db(true).unwrap();
    let (chainstate, _) = StacksChainState::open(
        naka_conf.is_mainnet(),
        naka_conf.burnchain.chain_id,
        &naka_conf.get_chainstate_path_str(),
        None,
    )
    .unwrap();

    let _block_height_pre_3_0 =
        NakamotoChainState::get_canonical_block_header(chainstate.db(), &sortdb)
            .unwrap()
            .unwrap()
            .stacks_block_height;

    info!("Nakamoto miner started...");
    blind_signer(&naka_conf, &signers, proposals_submitted);

    wait_for_first_naka_block_commit(60, &commits_submitted);
    
    let mut sender_nonce = 0;

    // instantiate BNSv2
    for (name, code) in [("commission-trait", COMMISSION_TRAIT), ("sip-09", SIP_009_TRAIT), ("BNS-V2", BNS_V2), ("zonefile-resolver", ZONEFILE_RESOLVER), ("namespace-airdrop", NAMESPACE_AIRDROP)].iter() {
        let contract_tx = make_contract_publish(
            &sender_sk,
            sender_nonce,
            (code.len() * 10) as u64,
            naka_conf.burnchain.chain_id,
            name,
            code
        );
        sender_nonce += 1;

        let info_before = get_chain_info_result(&naka_conf).unwrap();
        submit_tx(&http_origin, &contract_tx);

        // wait for it to be mined
        next_block_and(&mut btc_regtest_controller, 60, || {
            let info = get_chain_info_result(&naka_conf).unwrap();
            Ok(info.stacks_tip_height > info_before.stacks_tip_height)
        })
        .unwrap();
    }
    coord_channel
        .lock()
        .expect("Mutex poisoned")
        .stop_chains_coordinator();
    run_loop_stopper.store(false, Ordering::SeqCst);

    run_loop_thread.join().unwrap();
}

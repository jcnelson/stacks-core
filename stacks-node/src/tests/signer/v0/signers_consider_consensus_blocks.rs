// Copyright (C) 2026 Stacks Open Internet Foundation
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
use std::env;
use std::time::Duration;

use libsigner::v0::messages::RejectCode;
use stacks::chainstate::burn::db::sortdb::SortitionDB;
use stacks::chainstate::stacks::TenureChangeCause;
use stacks_signer::v0::tests::TEST_REJECT_ALL_BLOCK_PROPOSAL;
use tracing_subscriber::prelude::*;
use tracing_subscriber::{fmt, EnvFilter};

use crate::tests::neon_integrations::test_observer;
use crate::tests::signer::v0::{
    wait_for_block_proposal, wait_for_block_pushed, wait_for_block_rejections_from_signers,
    MultipleMinerTest,
};

#[test]
#[ignore]
/// Tests that signers will not reconsider blocks that they have already responded to that have been marked GloballyAccepted.
///
/// Test Setup:
/// - Distribute signers across two miners (4 on miner 1, 1 on miner 2)
/// - Need to be able to ensure the signer on miner 2 does not receive the block validate responses for the first proposed block
///
/// Test Execution:
/// 1. Configure the one signer on miner 2 to reject all proposals.
/// 2. Propose a block to all signers.
/// 3. The other 4 signers pre-commit/sign the block; the rejecting signer rejects.
/// 4. Allow rejecting signer to process proposals again.
/// 5. Repropose the same block.
/// 6. Confirm the previously rejecting signer does not reject the block again.
///
/// Test Assertions:
/// - Only the non-rejecting signers pre-commit/sign initially (rejecting signer does not).
/// - After reproposal, the previously rejecting signer does not reject the block again.
fn signers_do_not_reconsider_globally_accepted_and_responded_blocks() {
    if env::var("BITCOIND_TEST") != Ok("1".into()) {
        return;
    }

    tracing_subscriber::registry()
        .with(fmt::layer())
        .with(EnvFilter::from_default_env())
        .init();

    info!("------------------------- Test Setup -------------------------");

    // Create a multiple miner test with 5 signers
    // They will be distributed: 4 to miner 1, 1 to miner 2
    let num_signers = 5;
    let node_2_auth = "node_2".to_string();
    let node_1_auth = "node_1".to_string();
    let mut miners = MultipleMinerTest::new_with_signer_dist(
        num_signers,
        0,
        |config| {
            if config.endpoint.port() % 5 == 0 {
                config.auth_password = node_2_auth.clone();
            } else {
                config.auth_password = node_1_auth.clone();
            }
        },
        |config| {
            config.burnchain.pox_reward_length = Some(30);
            config.connection_options.auth_token = Some(node_1_auth.clone());
        },
        |config| {
            config.connection_options.auth_token = Some(node_2_auth.clone());
        },
        // Distribute signers so first 4 go to node 1, last 1 goes to node 2
        |port| if port % 5 == 0 { 1 } else { 0 },
        None,
    );
    let all_signers = miners.signer_test.signer_test_pks();
    let signer_configs = &miners.signer_test.signer_configs;
    let (conf_1, conf_2) = miners.get_node_configs();
    let mut approving_signers = Vec::new();
    let mut rejecting_signer = Vec::new();
    for (config, signer_pk) in signer_configs.iter().zip(all_signers.iter()) {
        if config.node_host == conf_2.node.rpc_bind {
            rejecting_signer.push(signer_pk.clone());
        } else {
            approving_signers.push(signer_pk.clone());
        }
    }
    assert_eq!(
        rejecting_signer.len(),
        1,
        "Expected exactly one signer to be assigned to miner 2"
    );
    let (miner_pk_1, _miner_pk_2) = miners.get_miner_public_keys();

    miners.pause_commits_miner_2();
    miners.boot_to_epoch_3();

    // Make sure we know which miner will win in the stalled block
    miners.pause_commits_miner_1();
    info!("------------------------- Mine First Block N -------------------------");

    let sortdb = SortitionDB::open(
        &conf_1.get_burn_db_file_path(),
        false,
        conf_1.get_burnchain().pox_constants,
    )
    .unwrap();
    // Mine an initial block to establish state
    miners
        .mine_bitcoin_block_and_tenure_change_tx(&sortdb, TenureChangeCause::BlockFound, 30)
        .expect("Failed to mine BTC block followed by tenure change tx");
    miners.submit_commit_miner_1(&sortdb);
    miners.signer_test.check_signer_states_normal();

    let info_before = miners.get_peer_info();
    info!("------------------------- Force 1 Signer to Reject blocks -------------------------");
    // Stall block validation submission on the signer connected to miner 2
    // This prevents that signer from validating the next proposed block
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(rejecting_signer.clone());

    info!("------------------------- Mine Block N+1 -------------------------");
    // Mine a new tenure which will issue a block proposal to all signers for its tenure change.
    miners.signer_test.mine_bitcoin_block();

    let block_proposal =
        wait_for_block_proposal(30, info_before.stacks_tip_height + 1, &miner_pk_1)
            .expect("Failed to receive block proposal for block N+1");
    let signer_signature_hash = block_proposal.block.header.signer_signature_hash();
    // The 4 signers on miner 1 should have validated and sent pre-commits
    // The 1 signer on miner 2 should immediately issue a block rejection.
    wait_for_block_pushed(30, &signer_signature_hash).expect("Failed to mine block N+1");
    info!("------------------------- Check Signer Rejected Due to TestingDirective -------------------------");
    let rejections =
        wait_for_block_rejections_from_signers(30, &signer_signature_hash, &rejecting_signer)
            .expect("Did not receive expected block rejection from rejecting signer");
    assert_eq!(
        rejections.len(),
        1,
        "Expected exactly one block rejection from rejecting signer"
    );
    assert_eq!(
        rejections[0].reason_code,
        RejectCode::TestingDirective,
        "Got an unexpected rejection reason from the rejecting signer"
    );

    info!("------------------------- Repropose {signer_signature_hash} -------------------------");
    test_observer::clear();
    TEST_REJECT_ALL_BLOCK_PROPOSAL.set(vec![]); // Unset the reject all block proposals condition so the rejecting signer will reprocess the block proposal.
    miners
        .signer_test
        .send_block_proposal(block_proposal, Duration::from_secs(30));
    assert!(
        wait_for_block_rejections_from_signers(30, &signer_signature_hash, &rejecting_signer)
            .is_err(),
        "Rejecting signer already issued a response and should not issue another"
    );
}

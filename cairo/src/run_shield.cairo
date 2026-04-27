/// Parameterized shield executable — takes witness data as input.
///
/// Public outputs (in order):
///   [auth_domain, pubkey_hash, v_note, fee, producer_fee,
///    cm_new, cm_producer, memo_ct_hash, producer_memo_ct_hash]
///
/// Argument layout (flattened felt252 array):
///   [auth_domain, pubkey_hash, v_note, fee, producer_fee,
///    cm_new, cm_producer, memo_ct_hash, producer_memo_ct_hash,
///    auth_root, auth_pub_seed, nk_tag, d_j, rseed, blind,
///    auth_idx,
///    wots_sig[0]..wots_sig[WOTS_CHAINS-1],
///    auth_siblings[0]..auth_siblings[AUTH_DEPTH-1],
///    producer_auth_root, producer_auth_pub_seed, producer_nk_tag,
///    producer_d_j, producer_rseed]
///
/// The shield circuit verifies an in-circuit WOTS+ signature under the
/// recipient's auth tree, binding the entire request payload. The wallet
/// must therefore be online to sign each shield (same model as transfer
/// and unshield).

use tzel::shield;
use tzel::{merkle, xmss_common};

#[executable]
fn main(args: Array<felt252>) -> Array<felt252> {
    let fixed_prefix: u32 = 16;
    let wots_chains: u32 = xmss_common::WOTS_CHAINS;
    let auth_depth: u32 = merkle::AUTH_DEPTH;
    let producer_witness: u32 = 5;
    let expected_len = fixed_prefix + wots_chains + auth_depth + producer_witness;
    assert(args.len() == expected_len, 'shield: bad arg len');

    let auth_domain = *args.at(0);
    let pubkey_hash = *args.at(1);
    let v_note: u64 = (*args.at(2)).try_into().unwrap();
    let fee: u64 = (*args.at(3)).try_into().unwrap();
    let producer_fee: u64 = (*args.at(4)).try_into().unwrap();
    let cm_new = *args.at(5);
    let cm_producer = *args.at(6);
    let memo_ct_hash = *args.at(7);
    let producer_memo_ct_hash = *args.at(8);
    let auth_root = *args.at(9);
    let auth_pub_seed = *args.at(10);
    let nk_tag = *args.at(11);
    let d_j = *args.at(12);
    let rseed = *args.at(13);
    let blind = *args.at(14);
    let auth_idx: u64 = (*args.at(15)).try_into().unwrap();

    let wots_start: u32 = fixed_prefix;
    let wots_sig = args.span().slice(wots_start, wots_chains);
    let auth_sib_start: u32 = wots_start + wots_chains;
    let auth_siblings = args.span().slice(auth_sib_start, auth_depth);
    let prod_start: u32 = auth_sib_start + auth_depth;

    let producer_auth_root = *args.at(prod_start);
    let producer_auth_pub_seed = *args.at(prod_start + 1);
    let producer_nk_tag = *args.at(prod_start + 2);
    let producer_d_j = *args.at(prod_start + 3);
    let producer_rseed = *args.at(prod_start + 4);

    shield::verify(
        auth_domain,
        pubkey_hash,
        v_note,
        fee,
        producer_fee,
        cm_new,
        cm_producer,
        memo_ct_hash,
        producer_memo_ct_hash,
        auth_root,
        auth_pub_seed,
        nk_tag,
        d_j,
        rseed,
        blind,
        auth_idx,
        wots_sig,
        auth_siblings,
        producer_auth_root,
        producer_auth_pub_seed,
        producer_nk_tag,
        producer_d_j,
        producer_rseed,
    )
}

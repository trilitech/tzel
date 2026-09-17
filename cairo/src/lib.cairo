pub mod blake_hash;
pub mod merkle;
pub mod run_shield;
pub mod run_transfer;
pub mod run_unshield;
pub mod shield;
pub mod transfer;
pub mod unshield;
pub mod xmss_common;

/// Canonical tez asset tag. Used by the multiasset commitment scheme:
/// every note commitment binds an asset tag, with `0` reserved for tez and
/// future bridge-defined tags taking any other felt252 value. In v1 only the
/// tez bridge is deployed, so shield/unshield assert their public-side asset
/// equals `ASSET_TEZ`; transfer's primary asset is witness-supplied and may
/// be any value.
pub const ASSET_TEZ: felt252 = 0;

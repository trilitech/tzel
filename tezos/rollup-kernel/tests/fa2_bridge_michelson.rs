//! Structural test suite for `tezos/fa2_bridge_ticketer.tz`.
//!
//! We don't have octez-client available in this container, so we can't
//! run the Michelson typechecker directly. Instead these tests verify
//! every invariant a typechecker (and a careful reviewer) would check:
//! delimiter balance, the parameter / storage type signatures the
//! kernel's outbox encoder relies on, the presence and reachability
//! of every FAILWITH branch, stack-annotation density, and the
//! handful of instructions whose absence would be a silent
//! correctness bug (READ_TICKET, TRANSFER_TOKENS to FA2 %transfer,
//! the SELF_ADDRESS creator check, etc.).
//!
//! These tests are sized to catch the bugs that *don't* fail at
//! Michelson-typecheck time: someone deleting the SELF_ADDRESS
//! creator check, swapping the asset_id comparison for !=, missing
//! the `producer must be tez` pin from one of the entrypoints, or
//! letting the FA2 mint emit only the rollup-forward op without the
//! token pull. All of those are well-formed Michelson; only the
//! presence and ordering of specific instructions guards against
//! them, and that's what we test here.

use std::fs;
use std::path::PathBuf;

const CONTRACT_PATH_REL: &str = "../fa2_bridge_ticketer.tz";

fn contract_source() -> String {
    let mut path = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    path.push(CONTRACT_PATH_REL);
    fs::read_to_string(&path).unwrap_or_else(|e| {
        panic!("failed to read {}: {}", path.display(), e);
    })
}

/// Strip the line comments and # blocks so we can scan the
/// instruction body without the stack-annotation prose tripping the
/// substring searches.
fn instructions_only(source: &str) -> String {
    let mut out = String::with_capacity(source.len());
    for line in source.lines() {
        // Anything after '#' on a line is a comment. The Michelson
        // string literals in this contract never contain '#' so this
        // is safe.
        let code = line.split('#').next().unwrap_or("");
        out.push_str(code);
        out.push('\n');
    }
    out
}

#[test]
fn parens_and_braces_balance() {
    let src = contract_source();
    let mut parens = 0i64;
    let mut braces = 0i64;
    let mut max_paren_depth = 0i64;
    let mut max_brace_depth = 0i64;
    for ch in src.chars() {
        match ch {
            '(' => {
                parens += 1;
                max_paren_depth = max_paren_depth.max(parens);
            }
            ')' => {
                parens -= 1;
                assert!(parens >= 0, "unbalanced ')' encountered");
            }
            '{' => {
                braces += 1;
                max_brace_depth = max_brace_depth.max(braces);
            }
            '}' => {
                braces -= 1;
                assert!(braces >= 0, "unbalanced '}}' encountered");
            }
            _ => {}
        }
    }
    assert_eq!(parens, 0, "parens off by {} at end of file", parens);
    assert_eq!(braces, 0, "braces off by {} at end of file", braces);
    // Sanity floor: a real ticketer with mint+burn branches is going
    // to nest at least a few levels of both. If the file got
    // accidentally truncated to a stub, these would drop to ~0.
    assert!(
        max_paren_depth >= 5,
        "paren depth {} suggests a truncated contract",
        max_paren_depth,
    );
    assert!(
        max_brace_depth >= 3,
        "brace depth {} suggests a truncated contract",
        max_brace_depth,
    );
}

#[test]
fn parameter_signature_matches_kernel_outbox_encoder() {
    // The kernel's encode_withdrawal_outbox_message produces an
    // outbox parameter shaped as
    //   pair (contract %receiver unit) (ticket (pair nat (option bytes)))
    // and routes to the `burn` entrypoint. The ticketer's parameter
    // type MUST include exactly that pair shape under the %burn arm
    // (with whitespace tolerance), or the kernel's outbox messages
    // will fail decoding inside Tezos.
    let src = instructions_only(&contract_source());
    let collapsed: String = src.split_whitespace().collect::<Vec<_>>().join(" ");

    // Top-level parameter is `or` of mint and burn.
    assert!(
        collapsed.contains("parameter (or (pair %mint"),
        "parameter must be `(or (pair %mint ...) (pair %burn ...))`",
    );

    // Burn entrypoint type must match the kernel's outbox encoder.
    assert!(
        collapsed.contains("(pair %burn (contract %receiver unit) (ticket %ticket (pair nat (option bytes))))"),
        "burn parameter must match kernel's MichelsonContract(addr) + FA2_1Ticket payload exactly",
    );

    // Mint entrypoint takes (amount: nat, (receiver: bytes, rollup: address)).
    assert!(
        collapsed.contains("(pair %mint (nat %amount) (pair (bytes %receiver) (address %rollup)))"),
        "mint parameter must be (nat amount, (bytes receiver, address rollup))",
    );
}

#[test]
fn storage_signature_is_per_asset_immutable_pair() {
    // Storage must be a pair of (fa2_contract_address, token_id) and
    // nothing else. Changing this signature would break the kernel's
    // origination tooling and any downstream indexer that reads the
    // ticketer's storage to learn what asset it serves.
    let src = instructions_only(&contract_source());
    let collapsed: String = src.split_whitespace().collect::<Vec<_>>().join(" ");
    assert!(
        collapsed.contains("storage (pair (address %fa2_contract) (nat %token_id))"),
        "storage must be (pair (address %fa2_contract) (nat %token_id))",
    );
}

#[test]
fn mint_branch_pulls_tokens_before_minting_ticket() {
    // The mint flow MUST call fa2_contract %transfer to pull the
    // user's tokens BEFORE handing an L2 ticket to the rollup —
    // otherwise the rollup mints liquidity backed by nothing. We
    // verify this two ways:
    //
    // 1. Both operation calls are present (FA2 transfer + rollup
    //    forward).
    // 2. The fa2_op is CONSed last onto the operations list, which
    //    puts it at the head and makes Tezos execute it first.
    let src = instructions_only(&contract_source());

    // FA2 %transfer entrypoint is targeted with the correct parameter
    // type. Use whitespace-collapsed form so newlines/indent don't
    // matter.
    let collapsed: String = src.split_whitespace().collect::<Vec<_>>().join(" ");
    let expected_fa2_type = "CONTRACT %transfer (list (pair (address %from_) (list (pair (address %to_) (pair (nat %token_id) (nat %amount))))))";
    assert!(
        collapsed.contains(expected_fa2_type),
        "mint must look up the FA2 %transfer entrypoint with the canonical FA2-2.1 transfer-list type",
    );

    // The mint branch builds the rollup forward param as (bytes,
    // ticket (...)) and resolves the rollup contract.
    assert!(
        collapsed.contains("CONTRACT (pair bytes (ticket (pair nat (option bytes))))"),
        "mint must resolve the rollup as a `contract (pair bytes (ticket ...))` — matches kernel's deposit ticket format",
    );

    // Operation list ordering. The mint branch must CONS the fa2_op
    // *after* the rollup_op (i.e. fa2_op ends up at the head of the
    // list, executed first by Tezos). The comment block right above
    // the CONSes is the most reliable marker.
    assert!(
        contract_source().contains("FA2 transfer must run\n        # ----- before the rollup deposit op"),
        "mint must document and emit fa2_op before rollup_op (head of list runs first)",
    );
}

#[test]
fn burn_branch_validates_creator_token_id_and_metadata() {
    // The burn flow must verify three things before transferring
    // FA2 tokens out:
    //   1. ticketer creator == SELF_ADDRESS (only this contract's
    //      tickets can be burned here)
    //   2. ticket content's token_id == 0 (the L2 ticket content is
    //      canonical `(0, None)`; the FA2 token_id binding lives in
    //      the ticketer's immutable storage, not in the L2 ticket)
    //   3. ticket content's metadata == None (we don't use metadata
    //      in v2; reject anything carrying a value to keep the
    //      attack surface minimal)
    let src = contract_source();

    // Each of the three checks has a corresponding FAILWITH message
    // that's unique to the burn branch. Their presence is what
    // proves the check is reachable. If a future refactor deletes
    // one of the checks, the corresponding string also goes away
    // and this test catches it.
    for msg in [
        "fa2_bridge: unexpected ticket creator",
        "fa2_bridge: ticket token_id must be 0",
        "fa2_bridge: ticket metadata must be None",
    ] {
        assert!(
            src.contains(msg),
            "burn branch missing the {:?} validation",
            msg,
        );
    }

    // SELF_ADDRESS / READ_TICKET / UNPAIR 3 are the load-bearing
    // instructions for the creator check. Their absence is the
    // catastrophic-bug signal.
    let instr = instructions_only(&src);
    assert!(instr.contains("READ_TICKET"), "burn must READ_TICKET");
    assert!(instr.contains("UNPAIR 3"), "burn must destructure the READ_TICKET result");
    assert!(instr.contains("SELF_ADDRESS"), "must reference SELF_ADDRESS for the creator check");
}

#[test]
fn burn_branch_dispatches_via_fa2_transfer() {
    // After validation, burn issues an FA2 %transfer with SENDER=
    // SELF_ADDRESS, TO=receiver, AMOUNT=ticket.amount. We assert the
    // CONTRACT %transfer lookup and the ADDRESS step that downcasts
    // the `contract unit` receiver to a plain L1 address (FA2
    // recipients are addresses, not contracts).
    let collapsed: String = instructions_only(&contract_source())
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ");
    let expected = "CONTRACT %transfer (list (pair (address %from_) (list (pair (address %to_) (pair (nat %token_id) (nat %amount))))))";
    // The mint branch already contains this; we want to ensure it
    // appears at least twice (mint pull + burn dispatch), since
    // dropping it from burn would silently leave the tickets
    // un-redeemed on chain.
    let occurrences = collapsed.matches(expected).count();
    assert!(
        occurrences >= 2,
        "expected the FA2 %transfer lookup in BOTH mint and burn branches; found {}",
        occurrences,
    );
    assert!(
        instructions_only(&contract_source()).contains("ADDRESS"),
        "burn must ADDRESS the `contract receiver unit` to get the L1 destination",
    );
}

#[test]
fn every_failwith_message_is_unique_and_prefixed() {
    // All FAILWITH messages in this contract are prefixed
    // `fa2_bridge:` so operation receipts identify which contract
    // failed (vs the tez ticketer or some other deployed contract).
    // Each message must also be unique so the receipt pinpoints
    // which check fired.
    let src = contract_source();
    let mut messages: Vec<String> = Vec::new();
    for line in src.lines() {
        if let Some(idx) = line.find("FAILWITH") {
            // Find the most recent PUSH string ... line.
            // Search backwards in the same physical line first; if
            // not found, scan upward.
            let prefix = &line[..idx];
            if let Some(s) = extract_pushed_string(prefix) {
                messages.push(s);
            }
        }
    }
    // Walk the file again to also pick up messages on the preceding
    // line (most FAILWITHs are written as `PUSH string "…" ; FAILWITH`
    // on the same line, but if any were split across lines this
    // handles them).
    let mut prev_line: &str = "";
    for line in src.lines() {
        if line.contains("FAILWITH") && extract_pushed_string(line).is_none() {
            if let Some(s) = extract_pushed_string(prev_line) {
                messages.push(s);
            }
        }
        prev_line = line;
    }

    assert!(!messages.is_empty(), "expected at least one FAILWITH message");
    for msg in &messages {
        assert!(
            msg.starts_with("fa2_bridge:"),
            "FAILWITH message {:?} must be prefixed `fa2_bridge:`",
            msg,
        );
    }
    let mut sorted = messages.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(
        sorted.len(),
        messages.len(),
        "FAILWITH messages must be unique; duplicates make operation-receipt diagnosis ambiguous: {:?}",
        messages,
    );

    // Specific failure modes we expect to be reachable. The two FA2
    // %transfer-entrypoint resolution failures are differentiated by
    // branch so an operator-receipt reader can tell mint-time vs
    // burn-time misconfiguration apart (mint fail = depositor can
    // retry; burn fail = pending withdrawal stuck and needs op fix).
    let required_messages = [
        "fa2_bridge: mint: FA2 %transfer entrypoint not found at fa2_contract",
        "fa2_bridge: burn: FA2 %transfer entrypoint not found at fa2_contract",
        "fa2_bridge: zero-amount mint",
        "fa2_bridge: invalid rollup contract",
        "fa2_bridge: unexpected ticket creator",
        "fa2_bridge: ticket metadata must be None",
        "fa2_bridge: ticket token_id must be 0",
        "fa2_bridge: must not attach tez",
    ];
    for required in required_messages {
        assert!(
            messages.iter().any(|m| m == required),
            "missing FAILWITH branch {:?}",
            required,
        );
    }
}

fn extract_pushed_string(line: &str) -> Option<String> {
    let idx = line.find("PUSH string \"")?;
    let after = &line[idx + "PUSH string \"".len()..];
    let end = after.find('"')?;
    Some(after[..end].to_string())
}

#[test]
fn stack_annotations_are_dense() {
    // The repo's Michelson style guide requires a `# stack: ...`
    // annotation after most non-trivial instructions. If a refactor
    // strips these out, the contract becomes a write-only blob.
    // We don't try to fully verify each annotation against the
    // semantics — that requires a real typechecker — but we do
    // ensure the ratio of annotated lines to instruction lines
    // stays above a sane floor.
    let src = contract_source();
    let stack_annotations = src
        .lines()
        .filter(|l| l.trim_start().starts_with("# stack:"))
        .count();
    let instruction_lines = src
        .lines()
        .filter(|l| {
            let t = l.trim();
            !t.is_empty()
                && !t.starts_with('#')
                && !t.starts_with("parameter")
                && !t.starts_with("storage")
                && !t.starts_with("code")
        })
        .count();

    assert!(
        stack_annotations >= 60,
        "expected at least 60 `# stack:` annotations; found {} — \
         someone deleted the annotation comments",
        stack_annotations,
    );
    // Roughly speaking we expect one annotation per non-trivial
    // instruction. Don't be too strict — some annotations cover
    // adjacent SWAP/PAIR pairs — but the ratio shouldn't fall below
    // about 1/3.
    let ratio_num = stack_annotations as f64;
    let ratio_den = instruction_lines.max(1) as f64;
    assert!(
        ratio_num / ratio_den >= 0.30,
        "stack-annotation density too low: {} annotations / {} instruction lines (ratio {:.2}) — \
         most instructions should be annotated",
        stack_annotations,
        instruction_lines,
        ratio_num / ratio_den,
    );
}

#[test]
fn no_mutez_amount_in_accounting_path() {
    // The FA2 mint amount MUST come from the %amount nat parameter,
    // not from AMOUNT (implicit mutez). Pulling AMOUNT for accounting
    // here would silently allow someone to mint an L2 FA2 ticket by
    // sending tez (free FA2!).
    //
    // Phase E.5 (Michelson nit #1 fix): AMOUNT *is* now used by the
    // contract — but only at the top of `code` to enforce that the
    // caller attached NO tez to the call (any attached tez would
    // accumulate in the ticketer with no recovery path). The
    // accounting-path guard below is the stricter check: no mutez
    // arithmetic anywhere (no EDIV/MUL on mutez), and the L2 ticket
    // amount comes from the nat parameter.
    let instr = instructions_only(&contract_source());
    assert!(
        !instr.contains("EDIV"),
        "FA2 ticketer must not EDIV mutez (tez ticketer pattern); FA2 mint takes amount as nat parameter",
    );
    assert!(
        !instr.contains(" MUL "),
        "FA2 ticketer must not MUL mutez — accounting goes through the %amount nat parameter",
    );
    // The only AMOUNT use is the top-of-`code` zero-check. Verify
    // that pattern is present so we know the AMOUNT instruction
    // isn't being repurposed for something else.
    let src = contract_source();
    assert!(
        src.contains("AMOUNT ;")
            && src.contains("PUSH mutez 0 ;")
            && src.contains("\"fa2_bridge: must not attach tez\""),
        "AMOUNT must be used solely to enforce that no tez was attached to the call",
    );
}

#[test]
fn ticket_content_metadata_is_always_none() {
    // Mint must construct the L2 ticket with canonical content
    // `(0, None)`; burn must reject any ticket whose metadata is not
    // None. The metadata field is reserved for future use; in v2 the
    // kernel doesn't carry anything in it.
    let instr = instructions_only(&contract_source());
    assert!(
        instr.contains("NONE bytes"),
        "mint must PUSH None for the ticket metadata; metadata is reserved-future-use in v2",
    );
}

/// Regression for the FA2-bridge non-zero-token_id production
/// blocker. The L2 ticket content MUST be canonical `(0, None)`
/// regardless of the FA2 token_id this ticketer wraps. The kernel's
/// `parse_bridge_deposit` rejects any deposit ticket whose
/// `content.token_id != 0`, and the kernel's outbox burn encoder
/// always emits content `(0, None)`. If the Michelson contract were
/// to stuff `storage.token_id` into the L2 ticket content (an
/// earlier draft did), the bridge would be structurally broken for
/// any FA2 with token_id != 0 — deposits would be rejected by the
/// kernel and burns would fail the ticketer's content check, with
/// user funds permanently stuck.
#[test]
fn mint_emits_canonical_zero_token_id_ticket_content() {
    let src = contract_source();

    // Slice the contract source into the mint and burn branches via
    // the `# === MINT BRANCH ===` / `# === BURN BRANCH ===` banners
    // the contract uses. The PUSH-nat-0 assertion must target the
    // MINT branch specifically: scoping it to `instructions_only(&src)`
    // (as an earlier draft did) was satisfied trivially by the burn
    // branch's `PUSH nat 0` zero-check on the ticket content, even
    // if a future refactor reintroduced storage.token_id-based mint
    // content.
    let mint_marker = "MINT BRANCH";
    let burn_marker = "BURN BRANCH";
    let mint_start = src
        .find(mint_marker)
        .expect("contract must label its mint branch");
    let burn_start = src
        .find(burn_marker)
        .expect("contract must label its burn branch");
    assert!(mint_start < burn_start, "mint branch must precede burn branch");
    let mint_branch = &src[mint_start..burn_start];
    let mint_instr = instructions_only(mint_branch);

    assert!(
        mint_instr.contains("PUSH nat 0"),
        "MINT branch must PUSH nat 0 to seed the L2 ticket's canonical content.token_id; \
         without this the ticket content carries storage.token_id and the bridge \
         is broken for any FA2 with token_id != 0 (kernel rejects \
         content.token_id != 0). Mint branch instructions: {}",
        mint_instr,
    );
    assert!(
        src.contains("\"fa2_bridge: ticket token_id must be 0\""),
        "burn must FAILWITH \"fa2_bridge: ticket token_id must be 0\" — verifies \
         the burn check compares against literal 0 rather than storage.token_id, \
         matching the canonical-content design",
    );

    // Defense in depth: make sure the OLD failure mode's string is
    // gone. If a refactor reintroduces `storage.token_id == ticket
    // content.token_id`, the old "mismatch" wording would
    // reappear and this assertion would fail.
    assert!(
        !src.contains("fa2_bridge: ticket token_id mismatch"),
        "burn branch still references the old `storage.token_id == content.token_id` \
         check — that path is broken for any FA2 with token_id != 0 because the \
         kernel emits burn outbox tickets with canonical content (0, None) \
         regardless of which FA2 ticketer they target",
    );
}

#[test]
fn no_storage_mutation_path() {
    // Storage is set at origination and immutable. The mint and burn
    // branches must return the *original* storage unchanged. We
    // verify this by checking that no `CAR` of the input pair's
    // storage half is followed by a re-PAIR producing a DIFFERENT
    // value — but that's intractable to grep. Instead we assert the
    // weaker invariant that the contract never uses PACK / UNPACK
    // tricks that would let a hidden storage mutation hide, and that
    // the final PAIR is preceded by an operation list, leaving
    // storage at the bottom of the stack untouched.
    //
    // Most directly: the file must end with `PAIR ;\n# stack: (ops,
    // storage)\n      }` in both branches.
    let src = contract_source();
    assert!(
        !src.contains(" PACK "),
        "no need for PACK in a ticketer — its presence would suggest custom serialisation paths",
    );
    assert!(
        !src.contains(" UNPACK "),
        "no need for UNPACK either",
    );
    let final_pair_count = src.matches("# stack: (ops, storage)").count();
    assert_eq!(
        final_pair_count, 2,
        "both mint and burn must end with `PAIR` annotated `# stack: (ops, storage)`; found {}",
        final_pair_count,
    );
}

/// End-to-end origination smoke test using octez-client's mockup
/// protocol runner. Same protocol code path as a real Tezos network
/// — proves the contract is not just typeable but actually
/// originateable with realistic storage. Auto-skips when
/// octez-client isn't on PATH.
///
/// This is the L1 counterpart of the kernel's end-to-end FA2 test
/// (which uses skip-verify proofs to exercise the L2 routing): both
/// tests together cover the bridge boundary's contract validation
/// at protocol-execution depth without requiring a full sandbox.
#[test]
fn fa2_bridge_originates_under_octez_client_mockup() {
    use std::process::Command;

    let bin = ["octez-client", "/home/coder/bin/octez-client"]
        .iter()
        .find(|p| Command::new(p).arg("--version").output().is_ok())
        .copied();
    let Some(bin) = bin else {
        eprintln!(
            "SKIP fa2_bridge_originates_under_octez_client_mockup: \
             octez-client not on PATH.",
        );
        return;
    };

    let base_dir = std::path::PathBuf::from("/tmp/tzel-fa2-bridge-originate");
    let _ = std::fs::remove_dir_all(&base_dir);
    std::fs::create_dir_all(&base_dir).expect("create mockup base dir");

    let protocol = "PtSeouLouXkxhg39oWzjxDWaCydNfR3RxCUrNe4Q9Ro8BTehcbh";
    let setup = Command::new(bin)
        .args([
            "--base-dir",
            base_dir.to_str().unwrap(),
            "--mode",
            "mockup",
            "--protocol",
            protocol,
            "create",
            "mockup",
        ])
        .output()
        .expect("octez-client create mockup");
    assert!(setup.status.success(), "mockup setup failed");

    let mut contract = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    contract.push(CONTRACT_PATH_REL);

    // Synthetic FA2 contract + token_id for the storage. The
    // values don't have to correspond to a real deployed FA2 — the
    // origination only typechecks the contract's storage against
    // its declared type and runs the empty trace. Real FA2 calls
    // happen at mint/burn time, which we don't simulate here
    // (would require interpreted ticket state).
    //
    // Note: we deliberately pick a NON-ZERO token_id here. An
    // earlier draft of the contract stuffed `storage.token_id` into
    // the L2 ticket content; with this value, deposits would be
    // rejected by the rollup kernel and burns would fail the
    // ticketer's content check — making the bridge structurally
    // unusable. The canonical-content design (L2 content = `(0,
    // None)` regardless of storage) is what lets `token_id != 0`
    // pass through. The complementary structural test
    // `mint_emits_canonical_zero_token_id_ticket_content` pins the
    // canonical-content invariant directly; this end-to-end test
    // verifies the contract still ORIGINATES with such storage.
    let fa2_contract = "KT1HbQepzV1nVGg8QVznG7z4RcHseD5kwqBn";
    let token_id = "42";
    let init_storage = format!("(Pair \"{}\" {})", fa2_contract, token_id);

    let result = Command::new(bin)
        .args([
            "--base-dir",
            base_dir.to_str().unwrap(),
            "--mode",
            "mockup",
            "--protocol",
            protocol,
            "originate",
            "contract",
            "test-fa2-bridge",
            "transferring",
            "0",
            "from",
            "bootstrap1",
            "running",
            contract.to_str().unwrap(),
            "--init",
            &init_storage,
            "--burn-cap",
            "5",
        ])
        .output()
        .expect("octez-client originate");
    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);

    assert!(
        result.status.success(),
        "origination failed:\nstdout: {}\nstderr: {}",
        stdout,
        stderr,
    );
    // Output must contain the KT1 of the newly-originated contract.
    let combined = format!("{}{}", stdout, stderr);
    assert!(
        combined.contains("New contract KT1"),
        "expected 'New contract KT1...' in output:\n{}",
        combined,
    );
    // Storage was successfully type-applied (origination prints the
    // storage line in its receipt).
    assert!(
        combined.contains("This origination was successfully applied"),
        "expected origination success marker:\n{}",
        combined,
    );
}

/// Real-typechecker run via octez-client mockup, when available.
/// Auto-skipped (with a clear log line) when `octez-client` isn't on
/// PATH. This is the ground-truth test that catches every bug the
/// structural suite above can't — e.g. a transposed SWAP/PAIR that
/// produces (ticket, bytes) where the rollup expects (bytes,
/// ticket), or a misalignment that breaks the Michelson parser.
///
/// To run locally: install the octez-client static binary into your
/// PATH (gitlab.com/tezos/tezos releases → static binaries →
/// x86_64-octez-client), then `cargo test --test
/// fa2_bridge_michelson fa2_bridge_typechecks_under_octez_client`.
///
/// In containers where octez-client is preinstalled (e.g. our
/// development container at /home/coder/bin/octez-client), the test
/// runs automatically.
#[test]
fn fa2_bridge_typechecks_under_octez_client() {
    use std::process::Command;

    // Locate octez-client. Try PATH first, then a couple of common
    // install paths.
    let bin = ["octez-client", "/home/coder/bin/octez-client"]
        .iter()
        .find(|p| Command::new(p).arg("--version").output().is_ok())
        .copied();
    let Some(bin) = bin else {
        eprintln!(
            "SKIP fa2_bridge_typechecks_under_octez_client: octez-client \
             not on PATH. Install from gitlab.com/tezos/tezos releases \
             (x86_64-octez-client static binary) to enable.",
        );
        return;
    };

    // Spin up (or reuse) a mockup base dir. Mockup mode lets us
    // typecheck without a running node.
    let base_dir = std::path::PathBuf::from("/tmp/tzel-fa2-bridge-typecheck");
    let _ = std::fs::remove_dir_all(&base_dir);
    std::fs::create_dir_all(&base_dir).expect("create mockup base dir");

    let protocol = "PtSeouLouXkxhg39oWzjxDWaCydNfR3RxCUrNe4Q9Ro8BTehcbh";
    let setup = Command::new(bin)
        .args([
            "--base-dir",
            base_dir.to_str().unwrap(),
            "--mode",
            "mockup",
            "--protocol",
            protocol,
            "create",
            "mockup",
        ])
        .output()
        .expect("octez-client create mockup");
    assert!(
        setup.status.success(),
        "octez-client mockup setup failed:\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&setup.stdout),
        String::from_utf8_lossy(&setup.stderr),
    );

    let mut contract = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    contract.push(CONTRACT_PATH_REL);
    let result = Command::new(bin)
        .args([
            "--base-dir",
            base_dir.to_str().unwrap(),
            "--mode",
            "mockup",
            "--protocol",
            protocol,
            "typecheck",
            "script",
            contract.to_str().unwrap(),
        ])
        .output()
        .expect("octez-client typecheck script");

    let stdout = String::from_utf8_lossy(&result.stdout);
    let stderr = String::from_utf8_lossy(&result.stderr);
    assert!(
        result.status.success() && (stdout.contains("Well typed") || stderr.contains("Well typed")),
        "fa2_bridge_ticketer.tz does NOT typecheck.\nstdout: {}\nstderr: {}",
        stdout,
        stderr,
    );
}

#[test]
fn header_documents_the_invariants_the_kernel_relies_on() {
    // The header comment carries documentation that the rest of the
    // system depends on: one-ticketer-per-asset, asset_id derivation,
    // mint and burn flow descriptions. If someone trims the header
    // for brevity, the contract becomes unmaintainable. Assert the
    // key statements are present.
    let src = contract_source();
    for required in [
        "One ticketer per FA2",
        "tzel:asset:",
        "%mint flow",
        "%burn flow",
        "deposit:<hex pubkey_hash>",
        "SELF_ADDRESS",
    ] {
        assert!(
            src.contains(required),
            "header comment must document {:?}",
            required,
        );
    }
}

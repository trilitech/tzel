//! Poseidon2-BN254 t=3 permutation + the wrap chip's `outputHash` Stage-2
//! sponge, ported byte-exactly from the gnark verifier reference.
//!
//! Ground truth (must match EXACTLY or the proof↔op binding fails):
//!   - in-circuit gadget: `~/git/stwo-gnark-tzel/verifier/circuit_verifier_chip.go`
//!     `CircuitVerifierChipLifted.outputHash` / `frToM31Lanes`;
//!   - off-circuit reference: `~/git/stwo-gnark-tzel/channel/offcircuit/
//!     outhash_poseidon2.go` `OutHashPoseidon2`.
//!
//! The permutation is the REAL Poseidon2-BN254 t=3 permutation (gnark-crypto
//! v0.19.0 constants, rF=8, rP=56, S-box x^5). It is a faithful re-port of the
//! stwo fork's `core::vcs_lifted::poseidon2_bn254_merkle::permute_t3`
//! (`~/git/stwo-fork-local`), reusing the EXACT round constants so the sponge
//! is identical to the Go `fri.Poseidon2Bn254Hasher` leaf sponge.
//!
//! Round constants (`RC_FULL_T3`, `RC_PART_T3`) are copied verbatim from
//! `stwo-fork-local/crates/stwo/src/core/vcs_lifted/poseidon2_bn254_constants.rs`
//! (canonical decimal, generated from gnark-crypto). DO NOT hand-edit.

use ark_bn254::Fr;
use ark_ff::{AdditiveGroup, Field, PrimeField};

mod constants {
    //! Poseidon2-BN254[t=3, rF=8, rP=56, d=5] round constants, canonical
    //! decimal. Copied verbatim from gnark-crypto v0.19.0 — the EXACT constants
    //! the gnark verifier consumes in-circuit. DO NOT hand-edit.
    #![allow(clippy::all)]

    pub(super) const RC_FULL_T3: [[&str; 3]; 8] = [
        ["19734078314593878970290714932418021832704551165884145844153660424917911822019", "8972348944577551660857719583477940787978966861674644402345929921010147007125", "20317573925582007699927898911681259731487973160243675131593067529402853753250", ],
        ["5274426587996548573599640406472301934743192856724573137285799077956511810959", "11102053784599032293416681353622561761662427465732179693204428511354680121798", "17390111482866691919454631068947840228311955897646724519479392563942376962904", ],
        ["13575387650805714802347354809855579681818981830578721029937023858818905216443", "14644086935598787559746273103472839901690710127424803330651639276348124495946", "12469487022026240558370619163792075897139316747578511448535492639408737019088", ],
        ["14653636367969407274565290761747371024037186460682351688851601507943041865606", "2018598375747339518474536967856816322138157705349052559428610272216619670379", "19624680133062816485517666617728760881753422930686007106752807029612528319862", ],
        ["13865655282288677269133919474917547323950364188868913422253989890214722242122", "3170232491892321075039497150438150525080491085988042149202401800449593557683", "1267349547466948813346264561094721551098408863423122526336978221136731201651", ],
        ["3598691090431426672396531798883939812588307078942857201837058139685589807442", "1287542830080175173452637429254852689321657752001946036993824740281928262604", "19729542244349527406046061885778850636913486371441470699419253810040034257049", ],
        ["5694106578906056975735332943295298425885884653062562526425056071103050707345", "16979863637656422999613506807535151883034404420921895416777894071411907845447", "17372598180831995470268190711051008718634972461698532795240768103616261910082", ],
        ["5077828966488845806486219765722521216523246666666040275956045291716391429297", "5006000714557822580597693054936201582941151752872187789826477406544840958839", "5443113630697030635592382678844687788901625246790838872291992779770434264657", ],
    ];

    pub(super) const RC_PART_T3: [&str; 56] = [
        "8219097043153089381116659644892967896190533226101155003150543525471171343965",
        "16205990840270797111009382611823046859724014467227357126859243310512456515903",
        "20068909902680678163419051354936660551341701914544742799767343960587988755233",
        "3158518493276664554020423194921577147865552265862732911862829463151636824036",
        "5691549687136184808131322839957046990930942399723233559624551518799779139099",
        "14742651350427819531793507721880646916254799695704182359084444488335467178564",
        "3579405979731024020808521127348479234678391194435730361762039070568748551878",
        "860935037057785844766939158888209728357479862308045348202681355243217409942",
        "5476022109365289540502919370827354337131001195008451895507019627324085167848",
        "5874874006976786137446682062650663707824350106726792562769710380135115164199",
        "938047074869000388728273214389485343682652197744972409647756681077316502876",
        "17180383944385639852273432525465690516676244326139147767726972839174909810678",
        "3288334830767177151020990315353821617905239886844997529108506525670072721484",
        "17413377746975786560230050304328469339133734512467445928610840130063662976217",
        "21653182590121391395718739212934575171132116143024719836811424901475223440094",
        "1081961990437390480428738841490481328365924185409738952594465805415715867367",
        "5707338973777584454287884603970360805370595326253962168144294467749506523257",
        "4641348915411338818146454186551109572234097885417070154974969526162510735786",
        "14349723458363515304753211658562859538872297775262043457113230753700093482914",
        "7576153613262637743484580902168942097079777828398045942246280622906576825666",
        "263975226676903365418515147570298584715573785898323379747596813593566450298",
        "19470343061092976183322170044267843819507548918721847845827076584624223267591",
        "804653682757100773482561776998186331322883121491089585736246015909340011620",
        "20633850283178282805133985751261813048351941304471895775698013888788379063958",
        "20034571392501607664785238149874444334099469742400590466655879849232923696332",
        "1107107464238730634760898570031789090881527204999053083491474097216707370602",
        "19423730596969998631919451276315735496046632853049672166023134350343101710823",
        "4377066878949723676356141315312609363247431430034630818499453775536548826791",
        "17830925264648323492079059689292919559113563645847512733894374802758884626477",
        "5089727713016606645200846434073776909354654925271283053729071881019881924088",
        "9848427958758864993394761496643061248691578635792336533285561312052130515151",
        "17931864121625823641416714914467014261644881792784119089307533953180986194278",
        "4634714059979318247332956290384755630721060414038071039045780454608688034007",
        "4184997917962849580222322183197090036217206046340868912538456145371163225177",
        "12401894459721068982334909376582036703151019496976814224883829261680735420555",
        "10255410817727536871096433704920767493105669182379211140673881166152679703890",
        "8197624822004878680760892251000533201669017527525878599578343166109230819288",
        "2457947412368847666906785091722001762012500079014688224672975163289002387501",
        "2781818268395468233354863228719630313682712404771236617837325416430175850968",
        "5051492164769685989207424203962539240502260695404188300926781188519303456884",
        "10156667235352381201860917247134239944031562921473664050571486173083662444930",
        "2969017704113095766301392335145956221000269786027913721978632223229037936051",
        "11037670951967909047150086331809778732664717478566065089568095939552913231284",
        "665971028821482768844596345818751923200290976079190591852110831132063890679",
        "14109792687853457251755757166030320558985110068104411630084494966655799275628",
        "674180192869437207676895541503137001599221247733462572863587842768615969771",
        "21399502106142876970212784216223904914241566574009380712531737179233191265467",
        "21206378134265231098318410177425617662090887545288053728111668169924066141313",
        "16871310953800490582163505125699377640798494835699988564475955647814806885243",
        "19291248235268850017323771536967121323802208771931871126029464821973571132414",
        "20687023388161466023217475349892280569560958169025721421665141946444358367825",
        "11753524635338367663998768292262730677406943334734368910802631608897328041366",
        "12428388534028072826988874900285888421506709929621472604082440110251734292962",
        "3369332753670270180325118847062110276802062411815139434472205784561534341953",
        "9022059842418075371066287889862707806495980900988635574353780425933064898511",
        "11517676931851736525547224579624703020289040985479207276129123614724640122021",
    ];
}

use core::str::FromStr;

/// Parse a canonical decimal string into `Fr` (compiled-in constants only).
fn fr_from_dec(s: &str) -> Fr {
    Fr::from_str(s).expect("constant must be a canonical decimal field element")
}

struct RoundConstantsT3 {
    full: [[Fr; 3]; 8],
    part: [Fr; 56],
}

fn rc_t3() -> &'static RoundConstantsT3 {
    use std::sync::OnceLock;
    static RC: OnceLock<RoundConstantsT3> = OnceLock::new();
    RC.get_or_init(|| {
        let mut full = [[Fr::ZERO; 3]; 8];
        for r in 0..8 {
            for lane in 0..3 {
                full[r][lane] = fr_from_dec(constants::RC_FULL_T3[r][lane]);
            }
        }
        let mut part = [Fr::ZERO; 56];
        for r in 0..56 {
            part[r] = fr_from_dec(constants::RC_PART_T3[r]);
        }
        RoundConstantsT3 { full, part }
    })
}

#[inline]
fn sbox(x: Fr) -> Fr {
    // x^5, S-box degree d=5 (matches gnark-crypto `DegreeSBox`).
    let x2 = x.square();
    let x4 = x2.square();
    x4 * x
}

#[inline]
fn mat_mul_external_t3(s: &mut [Fr; 3]) {
    // circ(2,1,1): out_i = s_i + sum
    let sum = s[0] + s[1] + s[2];
    s[0] = s[0] + sum;
    s[1] = s[1] + sum;
    s[2] = s[2] + sum;
}

#[inline]
fn mat_mul_internal_t3(s: &mut [Fr; 3]) {
    // [[2,1,1],[1,2,1],[1,1,3]]: out0=s0+sum, out1=s1+sum, out2=2*s2+sum
    let sum = s[0] + s[1] + s[2];
    s[0] = s[0] + sum;
    s[1] = s[1] + sum;
    s[2] = s[2].double() + sum;
}

/// Real Poseidon2-BN254 width-3 permutation (in place), matching gnark-crypto
/// v0.19.0 `Permutation.Permutation` for t=3 (rF=8 split 4+4, rP=56, S-box x^5).
fn permute_t3(state: &mut [Fr; 3]) {
    let rc = rc_t3();
    mat_mul_external_t3(state);
    for r in 0..4 {
        for lane in 0..3 {
            state[lane] += rc.full[r][lane];
        }
        state[0] = sbox(state[0]);
        state[1] = sbox(state[1]);
        state[2] = sbox(state[2]);
        mat_mul_external_t3(state);
    }
    for r in 0..56 {
        state[0] += rc.part[r];
        state[0] = sbox(state[0]);
        mat_mul_internal_t3(state);
    }
    for r in 4..8 {
        for lane in 0..3 {
            state[lane] += rc.full[r][lane];
        }
        state[0] = sbox(state[0]);
        state[1] = sbox(state[1]);
        state[2] = sbox(state[2]);
        mat_mul_external_t3(state);
    }
}

/// The wrap chip's `HashLeafQM31Lanes`: a t=3 rate-1 sponge over `Fr` items.
/// `state = [0,0,0]; for each item: state[0] += item; permute; digest = state[0]`.
fn hash_leaf_qm31_lanes(items: &[Fr]) -> Fr {
    let mut state = [Fr::ZERO; 3];
    for &x in items {
        state[0] += x;
        permute_t3(&mut state);
    }
    state[0]
}

/// `frToM31Lanes`: decompose a BN254 `Fr` into 8 M31 lanes, mirroring the chip's
/// `frToM31Lanes` / channel `drawBaseFelts`: 254 canonical little-endian bits,
/// regrouped into 8 × 32-bit words (the last word clamped to the 254-bit span),
/// each reduced mod `P = 2^31 - 1`.
fn fr_to_m31_lanes(e: &Fr) -> [u32; 8] {
    const M31_PRIME: u64 = (1 << 31) - 1;
    // Canonical representative in [0, r) as 4 little-endian u64 limbs.
    let limbs: [u64; 4] = e.into_bigint().0;
    let bit = |i: usize| -> u64 { (limbs[i / 64] >> (i % 64)) & 1 };

    let mut lanes = [0u32; 8];
    for w in 0..8 {
        let mut word: u64 = 0;
        let mut coeff: u64 = 1;
        let lo = 32 * w;
        let mut hi = 32 * (w + 1);
        if hi > 254 {
            hi = 254;
        }
        for i in lo..hi {
            if bit(i) == 1 {
                word += coeff;
            }
            coeff <<= 1;
        }
        lanes[w] = (word % M31_PRIME) as u32;
    }
    lanes
}

/// The wrap chip's `outputHash` Stage-2 over Poseidon2-BN254.
///
/// Absorb sequence (matches `CircuitVerifierChipLifted.outputHash` and the
/// off-circuit `OutHashPoseidon2`): the preprocessed root `Fr`, then each
/// output value's 4 M31 limbs as `Fr` (QM31 component order `a.0,a.1,b.0,b.1`).
/// Then `frToM31Lanes(digest)` → 8 M31 lanes.
///
/// `preprocessed_root` is the 32 raw bytes of `TreeRoots[0]` — a BN254 `Fr` in
/// BIG-ENDIAN (matching gnark's `Proof`/`fr.Element.SetBytes` wire encoding and
/// the channel-side `*big.Int` parse). `output_lanes` are the 8 M31 lanes of the
/// 2 claim output values (Stage-1 `output_hash`), no `U_VALUE`.
pub fn out_hash_poseidon2(preprocessed_root: &[u8; 32], output_lanes: &[u32]) -> [u32; 8] {
    // TreeRoots[0] is a big-endian 32-byte BN254 Fr (gnark wire encoding).
    let root_fr = Fr::from_be_bytes_mod_order(preprocessed_root);

    let mut absorbed = Vec::with_capacity(1 + output_lanes.len());
    absorbed.push(root_fr);
    for &lane in output_lanes.iter() {
        absorbed.push(Fr::from(lane as u64));
    }

    let digest = hash_leaf_qm31_lanes(&absorbed);
    fr_to_m31_lanes(&digest)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ark_ff::BigInteger;

    /// Sanity: the t=3 channel-sponge permutation matches the stwo-fork's
    /// `Bn254Channel` cross-vector (`mix_u64(0x1111222233334444)` checkpoint).
    /// `mix_u64` does `state = [digest, value, 2]; permute; digest = state[0]`
    /// from a fresh (zero) digest. This pins our permutation against the
    /// gnark-reference-validated fork constants independently of the sponge.
    #[test]
    fn permute_t3_matches_fork_mix_u64_vector() {
        let mut state = [Fr::ZERO, Fr::from(0x1111222233334444u64), Fr::from(2u64)];
        permute_t3(&mut state);
        let expected = Fr::from_str(
            "18335860630012600093476080647959457350446699604171237780436845943349943399218",
        )
        .unwrap();
        assert_eq!(state[0], expected, "permute_t3 mix_u64 checkpoint mismatch");
    }

    /// Golden cross-check vs the Go off-circuit `OutHashPoseidon2`.
    ///
    /// Golden lanes are produced by the Go reference harness
    /// `~/git/stwo-gnark-tzel/channel/offcircuit/outhash_golden_print_test.go`
    /// (`offcircuit.OutHashPoseidon2`, the pure-Go mirror of the in-circuit
    /// `CircuitVerifierChipLifted.outputHash`). Regenerate with that harness if
    /// the ABI changes:
    ///   GOCACHE=$HOME/.cache/go-build go test ./channel/offcircuit/ \
    ///       -run TestPrintOutHashGolden -v
    ///
    /// Each case: (root canonical-decimal, 8 output lanes, expected 8 lanes).
    /// Output lanes are the 2 claim output_values' 4 M31 limbs each
    /// (QM31 component order a.0,a.1,b.0,b.1) — NO U_VALUE (`Claim.OutputValues`
    /// has length N_RESERVED = 2 for the multiverifier root).
    #[test]
    fn out_hash_poseidon2_matches_go_golden() {
        let cases: [(&str, [u32; 8], [u32; 8]); 3] = [
            // fixture (real shape root + output_values)
            (
                "13519251900077559412859935703213531135994807629651282479517000995857517892527",
                [1763402576, 689144108, 517262139, 596324013, 742060404, 376654729, 1016220635, 87691908],
                [1731220680, 671354637, 1050799436, 898066049, 1205707151, 1594683397, 878197382, 59494376],
            ),
            // zeros
            (
                "0",
                [0, 0, 0, 0, 0, 0, 0, 0],
                [13806643, 1674001500, 145498308, 734486326, 712452599, 1994928903, 1896116140, 229500025],
            ),
            // small
            (
                "7",
                [1, 2, 3, 4, 5, 6, 7, 8],
                [1736512821, 1639433346, 1269796918, 1220714996, 1282894221, 988161044, 43891824, 57509436],
            ),
        ];

        for (root_dec, output_lanes, expected) in cases {
            let root = Fr::from_str(root_dec).unwrap();
            // 32-byte big-endian (gnark Fr wire encoding == TreeRoots[0] bytes).
            let be = root.into_bigint().to_bytes_be();
            let mut root_be = [0u8; 32];
            root_be[32 - be.len()..].copy_from_slice(&be);

            let got = out_hash_poseidon2(&root_be, &output_lanes);
            assert_eq!(
                got, expected,
                "OutHash Poseidon2 lanes mismatch for root {root_dec}"
            );
        }
    }
}

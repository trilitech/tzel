use std::collections::BTreeMap;
use std::collections::BTreeSet;
use std::env;
use std::fs;
use std::path::Path;

use wasmparser::{Name, Operator, Parser, Payload};

#[derive(Default, Debug, Clone)]
struct FloatOpCounts {
    f32: usize,
    f64: usize,
    simd_f32: usize,
    simd_f64: usize,
    simd_any: usize,
}

impl FloatOpCounts {
    fn total(&self) -> usize {
        self.f32 + self.f64 + self.simd_any
    }

    fn merge_from(&mut self, other: &Self) {
        self.f32 += other.f32;
        self.f64 += other.f64;
        self.simd_f32 += other.simd_f32;
        self.simd_f64 += other.simd_f64;
        self.simd_any += other.simd_any;
    }

    fn add_op(&mut self, op: &Operator<'_>) {
        use Operator::*;
        let op_name = format!("{op:?}");
        if op_name.starts_with("V128")
            || op_name.starts_with("I8x16")
            || op_name.starts_with("I16x8")
            || op_name.starts_with("I32x4")
            || op_name.starts_with("I64x2")
            || op_name.starts_with("F32x4")
            || op_name.starts_with("F64x2")
        {
            self.simd_any += 1;
        }
        match op {
            F32Abs
            | F32Neg
            | F32Ceil
            | F32Floor
            | F32Trunc
            | F32Nearest
            | F32Sqrt
            | F32Add
            | F32Sub
            | F32Mul
            | F32Div
            | F32Min
            | F32Max
            | F32Copysign
            | F32Eq
            | F32Ne
            | F32Lt
            | F32Gt
            | F32Le
            | F32Ge
            | F32ConvertI32S
            | F32ConvertI32U
            | F32ConvertI64S
            | F32ConvertI64U
            | F32DemoteF64
            | F32ReinterpretI32
            | F32Const { .. }
            | I32ReinterpretF32
            | I32TruncF32S
            | I32TruncF32U
            | I64TruncF32S
            | I64TruncF32U
            | I32TruncSatF32S
            | I32TruncSatF32U
            | I64TruncSatF32S
            | I64TruncSatF32U => self.f32 += 1,
            F64Abs
            | F64Neg
            | F64Ceil
            | F64Floor
            | F64Trunc
            | F64Nearest
            | F64Sqrt
            | F64Add
            | F64Sub
            | F64Mul
            | F64Div
            | F64Min
            | F64Max
            | F64Copysign
            | F64Eq
            | F64Ne
            | F64Lt
            | F64Gt
            | F64Le
            | F64Ge
            | F64ConvertI32S
            | F64ConvertI32U
            | F64ConvertI64S
            | F64ConvertI64U
            | F64PromoteF32
            | F64ReinterpretI64
            | F64Const { .. }
            | I64ReinterpretF64
            | I32TruncF64S
            | I32TruncF64U
            | I64TruncF64S
            | I64TruncF64U
            | I32TruncSatF64S
            | I32TruncSatF64U
            | I64TruncSatF64S
            | I64TruncSatF64U => self.f64 += 1,
            F32x4ExtractLane { .. }
            | F32x4ReplaceLane { .. }
            | F32x4Splat
            | F32x4Eq
            | F32x4Ne
            | F32x4Lt
            | F32x4Gt
            | F32x4Le
            | F32x4Ge
            | F32x4Ceil
            | F32x4Floor
            | F32x4Trunc
            | F32x4Nearest
            | F32x4Abs
            | F32x4Neg
            | F32x4Sqrt
            | F32x4Add
            | F32x4Sub
            | F32x4Mul
            | F32x4Div
            | F32x4Min
            | F32x4Max
            | F32x4PMin
            | F32x4PMax
            | I32x4TruncSatF32x4S
            | I32x4TruncSatF32x4U
            | F32x4ConvertI32x4S
            | F32x4ConvertI32x4U
            | F32x4DemoteF64x2Zero
            | I32x4RelaxedTruncF32x4S
            | I32x4RelaxedTruncF32x4U
            | F32x4RelaxedMadd
            | F32x4RelaxedNmadd
            | F32x4RelaxedMin
            | F32x4RelaxedMax => self.simd_f32 += 1,
            F64x2ExtractLane { .. }
            | F64x2ReplaceLane { .. }
            | F64x2Splat
            | F64x2Eq
            | F64x2Ne
            | F64x2Lt
            | F64x2Gt
            | F64x2Le
            | F64x2Ge
            | F64x2Ceil
            | F64x2Floor
            | F64x2Trunc
            | F64x2Nearest
            | F64x2Abs
            | F64x2Neg
            | F64x2Sqrt
            | F64x2Add
            | F64x2Sub
            | F64x2Mul
            | F64x2Div
            | F64x2Min
            | F64x2Max
            | F64x2PMin
            | F64x2PMax
            | I32x4TruncSatF64x2SZero
            | I32x4TruncSatF64x2UZero
            | F64x2ConvertLowI32x4S
            | F64x2ConvertLowI32x4U
            | F64x2PromoteLowF32x4
            | I32x4RelaxedTruncF64x2SZero
            | I32x4RelaxedTruncF64x2UZero
            | F64x2RelaxedMadd
            | F64x2RelaxedNmadd
            | F64x2RelaxedMin
            | F64x2RelaxedMax => self.simd_f64 += 1,
            _ => {}
        }
    }
}

fn main() -> Result<(), String> {
    let path = env::args()
        .nth(1)
        .ok_or_else(|| "usage: wasm-opscan <path-to-wasm>".to_string())?;
    let bytes = fs::read(&path).map_err(|e| format!("read {}: {}", path, e))?;

    let mut import_func_count = 0u32;
    let mut next_defined_func_index = 0u32;
    let mut function_names = BTreeMap::<u32, String>::new();
    let mut counts_by_func = BTreeMap::<u32, FloatOpCounts>::new();
    let mut calls_by_func = BTreeMap::<u32, Vec<u32>>::new();

    for payload in Parser::new(0).parse_all(&bytes) {
        match payload.map_err(|e| format!("parse {}: {}", path, e))? {
            Payload::ImportSection(section) => {
                for import in section.into_imports() {
                    let import = import.map_err(|e| format!("import parse: {}", e))?;
                    if matches!(import.ty, wasmparser::TypeRef::Func(_)) {
                        import_func_count += 1;
                    }
                }
            }
            Payload::CodeSectionEntry(body) => {
                let func_index = import_func_count + next_defined_func_index;
                next_defined_func_index += 1;
                let mut counts = FloatOpCounts::default();
                let mut callees = Vec::new();
                let mut reader = body.get_operators_reader().map_err(|e| e.to_string())?;
                while !reader.eof() {
                    let op = reader.read().map_err(|e| e.to_string())?;
                    counts.add_op(&op);
                    if let Operator::Call { function_index } = op {
                        callees.push(function_index);
                    }
                }
                if counts.total() > 0 {
                    counts_by_func.insert(func_index, counts);
                }
                if !callees.is_empty() {
                    calls_by_func.insert(func_index, callees);
                }
            }
            Payload::CustomSection(section) if section.name() == "name" => {
                if let wasmparser::KnownCustom::Name(name_reader) = section.as_known() {
                    for subsection in name_reader {
                        match subsection.map_err(|e| e.to_string())? {
                            Name::Function(map) => {
                                for naming in map {
                                    let naming = naming.map_err(|e| e.to_string())?;
                                    function_names.insert(naming.index, naming.name.to_string());
                                }
                            }
                            _ => {}
                        }
                    }
                }
            }
            _ => {}
        }
    }

    let total = counts_by_func
        .values()
        .fold(FloatOpCounts::default(), |mut acc, item| {
            acc.merge_from(item);
            acc
        });

    println!("file: {}", Path::new(&path).display());
    println!("functions_with_float_ops: {}", counts_by_func.len());
    println!("float_op_total: {}", total.total());
    println!("float_op_total_f32: {}", total.f32);
    println!("float_op_total_f64: {}", total.f64);
    println!("float_op_total_simd_f32: {}", total.simd_f32);
    println!("float_op_total_simd_f64: {}", total.simd_f64);
    println!("simd_op_total_any: {}", total.simd_any);

    let float_funcs: Vec<u32> = counts_by_func.keys().copied().collect();

    for (func_index, counts) in counts_by_func {
        let name = function_names
            .get(&func_index)
            .cloned()
            .unwrap_or_else(|| format!("<func:{}>", func_index));
        println!(
            "{}\tf32={}\tf64={}\tsimd_f32={}\tsimd_f64={}\tsimd_any={}\ttotal={}",
            name,
            counts.f32,
            counts.f64,
            counts.simd_f32,
            counts.simd_f64,
            counts.simd_any,
            counts.total()
        );
    }

    if !float_funcs.is_empty() {
        println!("--- callers ---");
        for float_func in float_funcs {
            let float_name = function_names
                .get(&float_func)
                .cloned()
                .unwrap_or_else(|| format!("<func:{}>", float_func));
            println!("target\t{}", float_name);
            let mut frontier = vec![float_func];
            let mut seen = BTreeSet::new();
            for depth in 1..=4 {
                let mut next = Vec::new();
                for target in frontier {
                    for (caller_index, callees) in &calls_by_func {
                        if seen.contains(caller_index) {
                            continue;
                        }
                        if callees.iter().any(|callee| *callee == target) {
                            seen.insert(*caller_index);
                            next.push(*caller_index);
                            let caller_name = function_names
                                .get(caller_index)
                                .cloned()
                                .unwrap_or_else(|| format!("<func:{}>", caller_index));
                            println!("caller_depth_{}\t{}", depth, caller_name);
                        }
                    }
                }
                if next.is_empty() {
                    break;
                }
                frontier = next;
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::FloatOpCounts;
    use wasmparser::Operator;

    #[test]
    fn total_counts_float_simd_once() {
        let mut counts = FloatOpCounts::default();
        counts.add_op(&Operator::F32x4Add);

        assert_eq!(counts.f32, 0);
        assert_eq!(counts.f64, 0);
        assert_eq!(counts.simd_f32, 1);
        assert_eq!(counts.simd_f64, 0);
        assert_eq!(counts.simd_any, 1);
        assert_eq!(counts.total(), 1);
    }

    #[test]
    fn total_includes_scalar_float_and_non_float_simd() {
        let mut counts = FloatOpCounts::default();
        counts.add_op(&Operator::F64Add);
        counts.add_op(&Operator::I32x4Add);

        assert_eq!(counts.f64, 1);
        assert_eq!(counts.simd_any, 1);
        assert_eq!(counts.simd_f32, 0);
        assert_eq!(counts.simd_f64, 0);
        assert_eq!(counts.total(), 2);
    }

    #[test]
    fn merge_from_preserves_simd_summary_counters() {
        let lhs = FloatOpCounts {
            f32: 2,
            f64: 3,
            simd_f32: 5,
            simd_f64: 7,
            simd_any: 11,
        };
        let rhs = FloatOpCounts {
            f32: 13,
            f64: 17,
            simd_f32: 19,
            simd_f64: 23,
            simd_any: 29,
        };

        let mut total = FloatOpCounts::default();
        total.merge_from(&lhs);
        total.merge_from(&rhs);

        assert_eq!(total.f32, 15);
        assert_eq!(total.f64, 20);
        assert_eq!(total.simd_f32, 24);
        assert_eq!(total.simd_f64, 30);
        assert_eq!(total.simd_any, 40);
        assert_eq!(total.total(), 75);
    }
}

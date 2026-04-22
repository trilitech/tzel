use std::str;

use crate::bundle::VerifyMeta;

const VERIFY_META_MAGIC: &[u8; 4] = b"TVM1";

#[cfg(test)]
pub fn encode(meta: &VerifyMeta) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    out.extend_from_slice(VERIFY_META_MAGIC);

    push_u32(&mut out, meta.n_pow_bits);
    push_len(&mut out, meta.n_preprocessed_columns)?;
    push_len(&mut out, meta.n_trace_columns)?;
    push_len(&mut out, meta.n_interaction_columns)?;
    push_vec_usize(&mut out, &meta.trace_columns_per_component)?;
    push_vec_usize(&mut out, &meta.interaction_columns_per_component)?;
    push_vec_bool(&mut out, &meta.cumulative_sum_columns)?;
    push_len(&mut out, meta.n_components)?;
    push_len(&mut out, meta.fri_log_trace_size)?;
    push_u32(&mut out, meta.fri_log_blowup);
    push_u32(&mut out, meta.fri_log_last_layer);
    push_len(&mut out, meta.fri_n_queries)?;
    push_u32(&mut out, meta.fri_fold_step);
    push_u32(&mut out, meta.interaction_pow_bits);
    push_u32(&mut out, meta.circuit_pow_bits);
    push_u32(&mut out, meta.circuit_fri_log_blowup);
    push_u32(&mut out, meta.circuit_fri_log_last_layer);
    push_len(&mut out, meta.circuit_fri_n_queries)?;
    push_u32(&mut out, meta.circuit_fri_fold_step);
    push_option_u32(&mut out, meta.circuit_lifting);
    push_vec_usize(&mut out, &meta.output_addresses)?;
    push_len(&mut out, meta.n_blake_gates)?;
    push_vec_string(&mut out, &meta.preprocessed_column_ids)?;
    push_vec_u32(&mut out, &meta.preprocessed_root)?;
    push_vec_u32(&mut out, &meta.public_output_values)?;

    Ok(out)
}

pub fn decode(bytes: &[u8]) -> Result<VerifyMeta, String> {
    let mut cursor = Cursor::new(bytes);
    if cursor.take_exact(VERIFY_META_MAGIC.len(), "invalid verify_meta header")?
        != VERIFY_META_MAGIC
    {
        return Err("invalid verify_meta header".into());
    }

    let meta = VerifyMeta {
        n_pow_bits: cursor.take_u32("invalid verify_meta n_pow_bits")?,
        n_preprocessed_columns: cursor.take_len("invalid verify_meta n_preprocessed_columns")?,
        n_trace_columns: cursor.take_len("invalid verify_meta n_trace_columns")?,
        n_interaction_columns: cursor.take_len("invalid verify_meta n_interaction_columns")?,
        trace_columns_per_component: cursor
            .take_vec_usize("invalid verify_meta trace_columns_per_component")?,
        interaction_columns_per_component: cursor
            .take_vec_usize("invalid verify_meta interaction_columns_per_component")?,
        cumulative_sum_columns: cursor
            .take_vec_bool("invalid verify_meta cumulative_sum_columns")?,
        n_components: cursor.take_len("invalid verify_meta n_components")?,
        fri_log_trace_size: cursor.take_len("invalid verify_meta fri_log_trace_size")?,
        fri_log_blowup: cursor.take_u32("invalid verify_meta fri_log_blowup")?,
        fri_log_last_layer: cursor.take_u32("invalid verify_meta fri_log_last_layer")?,
        fri_n_queries: cursor.take_len("invalid verify_meta fri_n_queries")?,
        fri_fold_step: cursor.take_u32("invalid verify_meta fri_fold_step")?,
        interaction_pow_bits: cursor.take_u32("invalid verify_meta interaction_pow_bits")?,
        circuit_pow_bits: cursor.take_u32("invalid verify_meta circuit_pow_bits")?,
        circuit_fri_log_blowup: cursor.take_u32("invalid verify_meta circuit_fri_log_blowup")?,
        circuit_fri_log_last_layer: cursor
            .take_u32("invalid verify_meta circuit_fri_log_last_layer")?,
        circuit_fri_n_queries: cursor.take_len("invalid verify_meta circuit_fri_n_queries")?,
        circuit_fri_fold_step: cursor.take_u32("invalid verify_meta circuit_fri_fold_step")?,
        circuit_lifting: cursor.take_option_u32("invalid verify_meta circuit_lifting")?,
        output_addresses: cursor.take_vec_usize("invalid verify_meta output_addresses")?,
        n_blake_gates: cursor.take_len("invalid verify_meta n_blake_gates")?,
        preprocessed_column_ids: cursor
            .take_vec_string("invalid verify_meta preprocessed_column_ids")?,
        preprocessed_root: cursor.take_vec_u32("invalid verify_meta preprocessed_root")?,
        public_output_values: cursor.take_vec_u32("invalid verify_meta public_output_values")?,
    };

    if !cursor.is_empty() {
        return Err("invalid verify_meta trailing bytes".into());
    }

    Ok(meta)
}

#[cfg(test)]
fn push_len(out: &mut Vec<u8>, value: usize) -> Result<(), String> {
    push_u32(
        out,
        u32::try_from(value).map_err(|_| "verify_meta field too large".to_string())?,
    );
    Ok(())
}

#[cfg(test)]
fn push_u32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
fn push_option_u32(out: &mut Vec<u8>, value: Option<u32>) {
    match value {
        Some(value) => {
            out.push(1);
            push_u32(out, value);
        }
        None => out.push(0),
    }
}

#[cfg(test)]
fn push_vec_u32(out: &mut Vec<u8>, values: &[u32]) -> Result<(), String> {
    push_len(out, values.len())?;
    for value in values {
        push_u32(out, *value);
    }
    Ok(())
}

#[cfg(test)]
fn push_vec_usize(out: &mut Vec<u8>, values: &[usize]) -> Result<(), String> {
    push_len(out, values.len())?;
    for value in values {
        push_len(out, *value)?;
    }
    Ok(())
}

#[cfg(test)]
fn push_vec_bool(out: &mut Vec<u8>, values: &[bool]) -> Result<(), String> {
    push_len(out, values.len())?;
    for value in values {
        out.push(u8::from(*value));
    }
    Ok(())
}

#[cfg(test)]
fn push_vec_string(out: &mut Vec<u8>, values: &[String]) -> Result<(), String> {
    push_len(out, values.len())?;
    for value in values {
        push_len(out, value.len())?;
        out.extend_from_slice(value.as_bytes());
    }
    Ok(())
}

struct Cursor<'a> {
    bytes: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, pos: 0 }
    }

    fn is_empty(&self) -> bool {
        self.pos == self.bytes.len()
    }

    fn take_exact(&mut self, len: usize, err: &'static str) -> Result<&'a [u8], String> {
        let end = self.pos.checked_add(len).ok_or_else(|| err.to_string())?;
        if end > self.bytes.len() {
            return Err(err.into());
        }
        let slice = &self.bytes[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    fn take_u8(&mut self, err: &'static str) -> Result<u8, String> {
        Ok(self.take_exact(1, err)?[0])
    }

    fn take_u32(&mut self, err: &'static str) -> Result<u32, String> {
        let bytes = self.take_exact(4, err)?;
        Ok(u32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    fn take_len(&mut self, err: &'static str) -> Result<usize, String> {
        usize::try_from(self.take_u32(err)?).map_err(|_| err.to_string())
    }

    fn take_option_u32(&mut self, err: &'static str) -> Result<Option<u32>, String> {
        match self.take_u8(err)? {
            0 => Ok(None),
            1 => Ok(Some(self.take_u32(err)?)),
            _ => Err(err.into()),
        }
    }

    fn take_vec_u32(&mut self, err: &'static str) -> Result<Vec<u32>, String> {
        let len = self.take_len(err)?;
        let mut values = Vec::with_capacity(len);
        for _ in 0..len {
            values.push(self.take_u32(err)?);
        }
        Ok(values)
    }

    fn take_vec_usize(&mut self, err: &'static str) -> Result<Vec<usize>, String> {
        let len = self.take_len(err)?;
        let mut values = Vec::with_capacity(len);
        for _ in 0..len {
            values.push(self.take_len(err)?);
        }
        Ok(values)
    }

    fn take_vec_bool(&mut self, err: &'static str) -> Result<Vec<bool>, String> {
        let len = self.take_len(err)?;
        let mut values = Vec::with_capacity(len);
        for _ in 0..len {
            values.push(match self.take_u8(err)? {
                0 => false,
                1 => true,
                _ => return Err(err.into()),
            });
        }
        Ok(values)
    }

    fn take_vec_string(&mut self, err: &'static str) -> Result<Vec<String>, String> {
        let len = self.take_len(err)?;
        let mut values = Vec::with_capacity(len);
        for _ in 0..len {
            let string_len = self.take_len(err)?;
            let bytes = self.take_exact(string_len, err)?;
            let value = str::from_utf8(bytes).map_err(|_| err.to_string())?;
            values.push(value.to_owned());
        }
        Ok(values)
    }
}

#[cfg(test)]
mod tests {
    use super::{decode, encode};
    use crate::bundle::VerifyMeta;

    #[test]
    fn verify_meta_codec_roundtrips() {
        let meta = VerifyMeta {
            n_pow_bits: 7,
            n_preprocessed_columns: 1,
            n_trace_columns: 2,
            n_interaction_columns: 3,
            trace_columns_per_component: vec![4, 5],
            interaction_columns_per_component: vec![6, 7],
            cumulative_sum_columns: vec![true, false, true],
            n_components: 8,
            fri_log_trace_size: 9,
            fri_log_blowup: 10,
            fri_log_last_layer: 11,
            fri_n_queries: 12,
            fri_fold_step: 13,
            interaction_pow_bits: 14,
            circuit_pow_bits: 15,
            circuit_fri_log_blowup: 16,
            circuit_fri_log_last_layer: 17,
            circuit_fri_n_queries: 18,
            circuit_fri_fold_step: 19,
            circuit_lifting: Some(20),
            output_addresses: vec![21, 22],
            n_blake_gates: 23,
            preprocessed_column_ids: vec!["alpha".into(), "beta".into()],
            preprocessed_root: vec![24, 25, 26, 27, 28, 29, 30, 31],
            public_output_values: vec![32, 33, 34, 35],
        };

        let encoded = encode(&meta).unwrap();
        let decoded = decode(&encoded).unwrap();
        assert_eq!(decoded.n_pow_bits, meta.n_pow_bits);
        assert_eq!(decoded.n_preprocessed_columns, meta.n_preprocessed_columns);
        assert_eq!(decoded.n_trace_columns, meta.n_trace_columns);
        assert_eq!(decoded.n_interaction_columns, meta.n_interaction_columns);
        assert_eq!(
            decoded.trace_columns_per_component,
            meta.trace_columns_per_component
        );
        assert_eq!(
            decoded.interaction_columns_per_component,
            meta.interaction_columns_per_component
        );
        assert_eq!(decoded.cumulative_sum_columns, meta.cumulative_sum_columns);
        assert_eq!(decoded.n_components, meta.n_components);
        assert_eq!(decoded.fri_log_trace_size, meta.fri_log_trace_size);
        assert_eq!(decoded.fri_log_blowup, meta.fri_log_blowup);
        assert_eq!(decoded.fri_log_last_layer, meta.fri_log_last_layer);
        assert_eq!(decoded.fri_n_queries, meta.fri_n_queries);
        assert_eq!(decoded.fri_fold_step, meta.fri_fold_step);
        assert_eq!(decoded.interaction_pow_bits, meta.interaction_pow_bits);
        assert_eq!(decoded.circuit_pow_bits, meta.circuit_pow_bits);
        assert_eq!(decoded.circuit_fri_log_blowup, meta.circuit_fri_log_blowup);
        assert_eq!(
            decoded.circuit_fri_log_last_layer,
            meta.circuit_fri_log_last_layer
        );
        assert_eq!(decoded.circuit_fri_n_queries, meta.circuit_fri_n_queries);
        assert_eq!(decoded.circuit_fri_fold_step, meta.circuit_fri_fold_step);
        assert_eq!(decoded.circuit_lifting, meta.circuit_lifting);
        assert_eq!(decoded.output_addresses, meta.output_addresses);
        assert_eq!(decoded.n_blake_gates, meta.n_blake_gates);
        assert_eq!(
            decoded.preprocessed_column_ids,
            meta.preprocessed_column_ids
        );
        assert_eq!(decoded.preprocessed_root, meta.preprocessed_root);
        assert_eq!(decoded.public_output_values, meta.public_output_values);
    }

    #[test]
    fn verify_meta_codec_rejects_invalid_header() {
        match decode(&[1, 2, 3]) {
            Ok(_) => panic!("expected invalid verify_meta header to fail"),
            Err(err) => assert!(err.contains("invalid verify_meta")),
        }
    }
}

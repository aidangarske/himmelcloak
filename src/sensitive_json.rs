/*
 * Himmelcloak native Keycloak authentication
 * SPDX-License-Identifier: LGPL-3.0-or-later OR GPL-3.0-or-later
 */
use std::ops::Deref;

use serde_json::{Map, Value};
use zeroize::{Zeroize, Zeroizing};

/// Owns parsed identity data until it is either rejected or passed to a caller.
pub(crate) struct SensitiveClaims(Value);

impl SensitiveClaims {
    pub(crate) fn new(value: Value) -> Self {
        Self(value)
    }

    pub(crate) fn into_value(mut self) -> Value {
        std::mem::take(&mut self.0)
    }
}

impl Deref for SensitiveClaims {
    type Target = Value;

    fn deref(&self) -> &Value {
        &self.0
    }
}

impl Drop for SensitiveClaims {
    fn drop(&mut self) {
        clear_claims(&mut self.0);
    }
}

pub(crate) fn clear_claims(value: &mut Value) {
    match value {
        Value::String(text) => text.zeroize(),
        Value::Array(items) => items.iter_mut().for_each(clear_claims),
        Value::Object(map) => {
            for (mut key, mut item) in std::mem::take(map) {
                key.zeroize();
                clear_claims(&mut item);
            }
        }
        _ => {}
    }
}

/// Parse JSON with a pre-sized, zeroizing string buffer. serde_json keeps an
/// ordinary scratch allocation for escaped strings, which may hold credentials
/// after a response or verified claim has been dropped.
pub(crate) fn parse(input: &[u8]) -> Option<SensitiveClaims> {
    let mut parser = Parser { input, offset: 0 };
    let value = SensitiveClaims::new(parser.value(0)?);
    parser.whitespace();
    (parser.offset == input.len()).then_some(value)
}

struct Parser<'a> {
    input: &'a [u8],
    offset: usize,
}

impl Parser<'_> {
    fn whitespace(&mut self) {
        while self
            .input
            .get(self.offset)
            .is_some_and(|byte| matches!(byte, b' ' | b'\n' | b'\r' | b'\t'))
        {
            self.offset += 1;
        }
    }

    fn consume(&mut self, byte: u8) -> bool {
        if self.input.get(self.offset) == Some(&byte) {
            self.offset += 1;
            true
        } else {
            false
        }
    }

    fn literal(&mut self, literal: &[u8], value: Value) -> Option<Value> {
        if !self.input.get(self.offset..)?.starts_with(literal) {
            return None;
        }
        self.offset += literal.len();
        Some(value)
    }

    fn value(&mut self, depth: usize) -> Option<Value> {
        if depth > 128 {
            return None;
        }
        self.whitespace();
        match self.input.get(self.offset)? {
            b'{' => self.object(depth),
            b'[' => self.array(depth),
            b'"' => self.string().map(Value::String),
            b't' => self.literal(b"true", Value::Bool(true)),
            b'f' => self.literal(b"false", Value::Bool(false)),
            b'n' => self.literal(b"null", Value::Null),
            b'-' | b'0'..=b'9' => self.number(),
            _ => None,
        }
    }

    fn object(&mut self, depth: usize) -> Option<Value> {
        self.offset += 1;
        let mut result = SensitiveClaims::new(Value::Object(Map::new()));
        self.whitespace();
        if self.consume(b'}') {
            return Some(result.into_value());
        }
        loop {
            let mut key = Zeroizing::new(self.string()?);
            self.whitespace();
            if !self.consume(b':') || result.0.as_object()?.contains_key(key.as_str()) {
                return None;
            }
            let value = self.value(depth + 1)?;
            result
                .0
                .as_object_mut()?
                .insert(std::mem::take(&mut *key), value);
            self.whitespace();
            if self.consume(b'}') {
                return Some(result.into_value());
            }
            if !self.consume(b',') {
                return None;
            }
            self.whitespace();
        }
    }

    fn array(&mut self, depth: usize) -> Option<Value> {
        self.offset += 1;
        let mut result = SensitiveClaims::new(Value::Array(Vec::new()));
        self.whitespace();
        if self.consume(b']') {
            return Some(result.into_value());
        }
        loop {
            result.0.as_array_mut()?.push(self.value(depth + 1)?);
            self.whitespace();
            if self.consume(b']') {
                return Some(result.into_value());
            }
            if !self.consume(b',') {
                return None;
            }
        }
    }

    fn number(&mut self) -> Option<Value> {
        let start = self.offset;
        while self
            .input
            .get(self.offset)
            .is_some_and(|byte| matches!(byte, b'-' | b'+' | b'.' | b'e' | b'E' | b'0'..=b'9'))
        {
            self.offset += 1;
        }
        serde_json::from_slice::<serde_json::Number>(&self.input[start..self.offset])
            .ok()
            .map(Value::Number)
    }

    fn string(&mut self) -> Option<String> {
        if !self.consume(b'"') {
            return None;
        }
        let start = self.offset;
        let mut end = start;
        while let Some(&byte) = self.input.get(end) {
            if byte == b'"' {
                break;
            }
            end += if byte == b'\\' { 2 } else { 1 };
        }
        if self.input.get(end) != Some(&b'"') {
            return None;
        }
        let raw = &self.input[start..end];
        // Every escape decodes to no more bytes than its source representation.
        // This capacity prevents reallocations that could free plaintext copies.
        let mut decoded = Zeroizing::new(Vec::with_capacity(raw.len()));
        let mut index = 0;
        while let Some(&byte) = raw.get(index) {
            index += 1;
            if byte < 0x20 {
                return None;
            }
            if byte != b'\\' {
                decoded.push(byte);
                continue;
            }
            let escaped = *raw.get(index)?;
            index += 1;
            match escaped {
                b'"' | b'\\' | b'/' => decoded.push(escaped),
                b'b' => decoded.push(8),
                b'f' => decoded.push(12),
                b'n' => decoded.push(b'\n'),
                b'r' => decoded.push(b'\r'),
                b't' => decoded.push(b'\t'),
                b'u' => {
                    let mut codepoint = u32::from(hex4(raw, &mut index)?);
                    if (0xd800..=0xdbff).contains(&codepoint) {
                        if raw.get(index..index + 2)? != b"\\u" {
                            return None;
                        }
                        index += 2;
                        let low = u32::from(hex4(raw, &mut index)?);
                        if !(0xdc00..=0xdfff).contains(&low) {
                            return None;
                        }
                        codepoint = 0x10000 + ((codepoint - 0xd800) << 10) + low - 0xdc00;
                    }
                    let scalar = char::from_u32(codepoint)?;
                    let mut utf8 = Zeroizing::new([0u8; 4]);
                    decoded.extend_from_slice(scalar.encode_utf8(&mut *utf8).as_bytes());
                }
                _ => return None,
            }
        }
        self.offset = end + 1;
        match String::from_utf8(std::mem::take(&mut *decoded)) {
            Ok(value) => Some(value),
            Err(error) => {
                let _invalid = Zeroizing::new(error.into_bytes());
                None
            }
        }
    }
}

fn hex4(raw: &[u8], index: &mut usize) -> Option<u16> {
    let digits = raw.get(*index..*index + 4)?;
    *index += 4;
    let mut value = 0u16;
    for &digit in digits {
        value = (value << 4)
            | u16::from(match digit {
                b'0'..=b'9' => digit - b'0',
                b'a'..=b'f' => digit - b'a' + 10,
                b'A'..=b'F' => digit - b'A' + 10,
                _ => return None,
            });
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::parse;
    use serde_json::json;

    #[test]
    fn parses_escaped_identity_attributes() {
        let value = parse(
            br#"{"sub":"alice","profile":{"name":"A\"B","note":"line\n2","emoji":"\uD83D\uDE00"}}"#,
        )
        .unwrap();
        assert_eq!(value["profile"]["name"], "A\"B");
        assert_eq!(value["profile"]["note"], "line\n2");
        assert_eq!(value["profile"]["emoji"], "😀");
    }

    #[test]
    fn rejects_invalid_or_duplicate_claims() {
        for input in [
            &br#"{"sub":"a","sub":"b"}"#[..],
            &br#"{"sub":"\uD800"}"#[..],
            &br#"{"sub":"bad\q"}"#[..],
            &br#"{"sub":"ok"} extra"#[..],
            &br#"[1,]"#[..],
            b"{\"sub\":\"raw\nnewline\"}",
        ] {
            assert!(parse(input).is_none());
        }
    }

    #[test]
    fn matches_standard_json_values_for_keycloak_shapes() {
        for expected in [
            json!({"iss":"https://keycloak.example/realms/test","aud":["client","account"],"exp":1920000000,"azp":null}),
            json!({"sub":"alice","profile":{"quote":"A\"B","slash":"\\","control":"\u{0}\n","emoji":"😀"}}),
            json!([true, false, null, -3, 0, 1.5, 1e-10]),
        ] {
            let encoded = serde_json::to_vec(&expected).unwrap();
            assert_eq!(*parse(&encoded).unwrap(), expected);
        }
    }
}

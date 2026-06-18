use crate::ValidationError;

pub fn validate_non_empty(value: &str, label: &str) -> Result<(), ValidationError> {
    if value.trim().is_empty() {
        return Err(ValidationError::empty_field(label));
    }
    Ok(())
}

// `parse_public_key_material` migrated to `core_principals::parse` per ADR 156.

pub fn required_field(
    fields: &std::collections::BTreeMap<String, String>,
    name: &str,
) -> Result<String, ValidationError> {
    fields
        .get(name)
        .cloned()
        .ok_or_else(|| ValidationError::empty_field(name))
}

pub fn optional_non_empty_field(
    fields: &std::collections::BTreeMap<String, String>,
    name: &str,
) -> Option<String> {
    fields.get(name).and_then(|value| {
        if value.is_empty() {
            None
        } else {
            Some(value.clone())
        }
    })
}

pub fn parse_bool_field(
    fields: &std::collections::BTreeMap<String, String>,
    name: &str,
) -> Result<bool, ValidationError> {
    match required_field(fields, name)?.as_str() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(ValidationError::invalid_format(format!(
            "invalid boolean canonical field: {name}"
        ))),
    }
}

pub fn canonical_record(record_type: &str, fields: &[(&str, String)]) -> Vec<u8> {
    let capacity = 5
        + record_type.len()
        + 1
        + fields
            .iter()
            .map(|(k, v)| k.len() + 1 + v.len() + 1)
            .sum::<usize>();
    let mut out = String::with_capacity(capacity);
    out.push_str("type=");
    out.push_str(record_type);
    out.push('\n');
    for (name, value) in fields {
        out.push_str(name);
        out.push('=');
        out.push_str(&escape_canonical(value));
        out.push('\n');
    }
    out.into_bytes()
}

pub fn parse_canonical_record(
    payload: &[u8],
) -> Result<(String, std::collections::BTreeMap<String, String>), ValidationError> {
    let payload = std::str::from_utf8(payload).map_err(|err| {
        ValidationError::invalid_format(format!("canonical payload is not utf-8: {err}"))
    })?;
    let mut lines = payload.lines();
    let type_line = lines.next().ok_or_else(|| {
        ValidationError::invalid_format("canonical payload must contain a type line")
    })?;
    let record_type = type_line.strip_prefix("type=").ok_or_else(|| {
        ValidationError::invalid_format("canonical payload must start with type=")
    })?;

    let mut fields = std::collections::BTreeMap::new();
    for line in lines {
        let Some((name, value)) = split_canonical_field(line) else {
            return Err(ValidationError::invalid_format(
                "invalid canonical field line",
            ));
        };
        fields.insert(name.to_string(), unescape_canonical(value)?);
    }

    Ok((record_type.to_string(), fields))
}

pub fn escape_canonical(value: &str) -> String {
    let mut out = String::new();
    for ch in value.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\t' => out.push_str("\\t"),
            '=' => out.push_str("\\="),
            _ => out.push(ch),
        }
    }
    out
}

pub fn unescape_canonical(value: &str) -> Result<String, ValidationError> {
    let mut out = String::new();
    let mut chars = value.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            out.push(ch);
            continue;
        }

        let escaped = chars
            .next()
            .ok_or_else(|| ValidationError::invalid_format("unterminated canonical escape"))?;
        match escaped {
            '\\' => out.push('\\'),
            'n' => out.push('\n'),
            't' => out.push('\t'),
            '=' => out.push('='),
            _ => {
                return Err(ValidationError::invalid_format(
                    "canonical payload contains an unknown escape sequence",
                ));
            }
        }
    }
    Ok(out)
}

pub fn bytes_to_hex(bytes: &[u8]) -> String {
    hex::encode(bytes)
}

pub fn hex_to_bytes(value: &str) -> Result<Vec<u8>, ValidationError> {
    hex::decode(value).map_err(|err| ValidationError::invalid_format(format!("invalid hex: {err}")))
}

pub fn split_canonical_field(line: &str) -> Option<(&str, &str)> {
    let bytes = line.as_bytes();
    let mut escaped = false;
    for (index, byte) in bytes.iter().enumerate() {
        if escaped {
            escaped = false;
            continue;
        }
        match byte {
            b'\\' => escaped = true,
            b'=' => return Some((&line[..index], &line[index + 1..])),
            _ => {}
        }
    }
    None
}

pub fn decode_hex_nibble(byte: u8) -> Result<u8, ValidationError> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'a'..=b'f' => Ok(byte - b'a' + 10),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(ValidationError::invalid_format("invalid hex character")),
    }
}

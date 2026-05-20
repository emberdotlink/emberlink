//! Relay WebSocket client — one-shot connect/send/receive/close.
//!
//! Implements the relay text protocol over WebSocket Binary frames,
//! matching the pattern used by `emberlink-relay`.

use tungstenite::Message;

/// Send a single command to the relay and return the text response.
///
/// Opens a WebSocket connection, sends `command` as a Binary frame,
/// reads one response frame, then closes the connection.
pub fn relay_command(relay_url: &str, command: &str) -> Result<String, String> {
    let (mut ws, _response) =
        tungstenite::connect(relay_url).map_err(|e| format!("WebSocket connect failed: {e}"))?;

    ws.send(Message::Binary(command.as_bytes().to_vec().into()))
        .map_err(|e| format!("WebSocket send failed: {e}"))?;

    let reply = ws
        .read()
        .map_err(|e| format!("WebSocket read failed: {e}"))?;

    let text = match reply {
        Message::Text(t) => t.to_string(),
        Message::Binary(b) => {
            String::from_utf8(b.to_vec()).map_err(|e| format!("non-UTF-8 response: {e}"))?
        }
        other => return Err(format!("unexpected frame type: {other:?}")),
    };

    let _ = ws.close(None);

    Ok(text)
}

/// Send REQUEST_GRANT to the relay and return the request ID on success.
///
/// Wire format: `REQUEST_GRANT <target_id> <requester_id> <scope> <justification>`
/// Expected response: `OK <request-id>` or an error string.
pub fn request_grant(
    relay_url: &str,
    target_id: &str,
    requester_id: &str,
    scope: &str,
    justification: &str,
) -> Result<String, String> {
    let cmd = format!("REQUEST_GRANT {target_id} {requester_id} {scope} {justification}");
    let response = relay_command(relay_url, &cmd)?;

    if let Some(request_id) = response.strip_prefix("OK ") {
        Ok(request_id.trim().to_string())
    } else {
        Err(response)
    }
}

/// Parsed grant request info returned by FETCH_GRANT_REQUESTS.
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct RelayGrantRequest {
    pub request_id: String,
    pub target_id: String,
    pub requester_id: String,
    pub scope: String,
    pub justification: String,
    pub created_at: u64,
    pub status: String,
}

/// Fetch pending grant requests for a target identity from the relay.
///
/// Wire format: `FETCH_GRANT_REQUESTS <target_id>`
/// Response: one JSON object per line, or `NONE` if empty.
pub fn fetch_grant_requests(
    relay_url: &str,
    target_id: &str,
) -> Result<Vec<RelayGrantRequest>, String> {
    let cmd = format!("FETCH_GRANT_REQUESTS {target_id}");
    let response = relay_command(relay_url, &cmd)?;

    if response.trim() == "NONE" {
        return Ok(Vec::new());
    }

    let mut results = Vec::new();
    for line in response.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        let req: RelayGrantRequest = serde_json::from_str(trimmed)
            .map_err(|e| format!("invalid grant request JSON: {e}"))?;
        results.push(req);
    }
    Ok(results)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_ok_response() {
        let response = "OK gr-abc123";
        let id = response.strip_prefix("OK ").unwrap().trim();
        assert_eq!(id, "gr-abc123");
    }

    #[test]
    fn parse_none_response() {
        let result = parse_fetch_response("NONE");
        assert!(result.is_ok());
        assert!(result.unwrap().is_empty());
    }

    #[test]
    fn parse_json_lines_response() {
        let json = r#"{"request_id":"gr-1","target_id":"alice","requester_id":"bot","scope":"read","justification":"test","created_at":1000,"status":"pending"}"#;
        let result = parse_fetch_response(json);
        assert!(result.is_ok());
        let requests = result.unwrap();
        assert_eq!(requests.len(), 1);
        assert_eq!(requests[0].request_id, "gr-1");
        assert_eq!(requests[0].status, "pending");
    }

    /// Helper to test response parsing without a real WebSocket connection.
    fn parse_fetch_response(response: &str) -> Result<Vec<RelayGrantRequest>, String> {
        if response.trim() == "NONE" {
            return Ok(Vec::new());
        }
        let mut results = Vec::new();
        for line in response.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let req: RelayGrantRequest = serde_json::from_str(trimmed)
                .map_err(|e| format!("invalid grant request JSON: {e}"))?;
            results.push(req);
        }
        Ok(results)
    }
}

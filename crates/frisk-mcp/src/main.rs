use recon_core::Target;
use serde_json::{json, Value};
use std::path::PathBuf;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use url::Url;

const PROTOCOL_VERSION: &str = "2024-11-05";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mut reader = BufReader::new(tokio::io::stdin()).lines();
    let mut stdout = tokio::io::stdout();
    while let Some(line) = reader.next_line().await? {
        if line.trim().is_empty() {
            continue;
        }
        let req: Value = match serde_json::from_str(&line) {
            Ok(v) => v,
            Err(_) => continue,
        };
        if let Some(resp) = handle_request(&req).await {
            stdout
                .write_all(serde_json::to_string(&resp)?.as_bytes())
                .await?;
            stdout.write_all(b"\n").await?;
            stdout.flush().await?;
        }
    }
    Ok(())
}

/// Returns Some(response) for requests, None for notifications (no `id`).
async fn handle_request(req: &Value) -> Option<Value> {
    let method = req.get("method")?.as_str()?;
    let id = req.get("id").cloned();
    match method {
        "initialize" => Some(json!({
            "jsonrpc": "2.0", "id": id,
            "result": {
                "protocolVersion": PROTOCOL_VERSION,
                "capabilities": { "tools": {} },
                "serverInfo": { "name": "frisk-mcp", "version": env!("CARGO_PKG_VERSION") }
            }
        })),
        "notifications/initialized" => None,
        "tools/list" => Some(json!({
            "jsonrpc": "2.0", "id": id,
            "result": { "tools": [{
                "name": "frisk_scan",
                "description": "Run a passive security/audit pre-flight on a URL and/or a local repo path. Returns a graded JSON report covering security headers, TLS, tech-stack/EOL, secrets/PII, and dependency CVEs.",
                "inputSchema": {
                    "type": "object",
                    "properties": {
                        "url": { "type": "string", "description": "Target URL, e.g. https://example.com" },
                        "repo": { "type": "string", "description": "Local repository path to scan for secrets and vulnerable dependencies" }
                    }
                }
            }] }
        })),
        "tools/call" => {
            let params = req.get("params")?;
            let name = params.get("name").and_then(|v| v.as_str()).unwrap_or("");
            if name != "frisk_scan" {
                return Some(json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":format!("unknown tool: {name}")}}));
            }
            let args = params
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| json!({}));
            let url = args.get("url").and_then(|v| v.as_str()).and_then(|u| {
                Url::parse(u)
                    .or_else(|_| Url::parse(&format!("https://{u}")))
                    .ok()
            });
            let repo = args.get("repo").and_then(|v| v.as_str()).map(PathBuf::from);
            if url.is_none() && repo.is_none() {
                return Some(json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":"error: provide a url and/or repo argument"}],"isError":true}}));
            }
            let target = Target { url, repo };
            let report = recon_core::registry::run(&target, &recon_core::all_detectors()).await;
            let text = serde_json::to_string_pretty(&report).unwrap_or_else(|_| "{}".to_string());
            Some(json!({"jsonrpc":"2.0","id":id,"result":{"content":[{"type":"text","text":text}]}}))
        }
        _ => id.map(
            |id| json!({"jsonrpc":"2.0","id":id,"error":{"code":-32601,"message":format!("method not found: {method}")}}),
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn initialize_reports_server_info() {
        let req = json!({"jsonrpc":"2.0","id":1,"method":"initialize","params":{}});
        let resp = handle_request(&req).await.unwrap();
        assert_eq!(resp["result"]["serverInfo"]["name"], "frisk-mcp");
        assert_eq!(resp["result"]["protocolVersion"], PROTOCOL_VERSION);
    }

    #[tokio::test]
    async fn tools_list_exposes_frisk_scan() {
        let req = json!({"jsonrpc":"2.0","id":2,"method":"tools/list"});
        let resp = handle_request(&req).await.unwrap();
        assert_eq!(resp["result"]["tools"][0]["name"], "frisk_scan");
    }

    #[tokio::test]
    async fn notification_returns_no_response() {
        let req = json!({"jsonrpc":"2.0","method":"notifications/initialized"});
        assert!(handle_request(&req).await.is_none());
    }
}

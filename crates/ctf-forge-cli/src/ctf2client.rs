//! Native CTF2 Open API read client (ureq + rustls) — the Rust replacement
//! for the retired Python auto-ctf fallback (`refs/oracle/auto-ctf-python/`).
//!
//! Scope: user Open API read surface with a PAT. Token source: $CTF2_TOKEN
//! env or api-key.txt in the repo root; never printed or persisted.
//! Write endpoints (flag submit / env start / tickets / profile) are
//! intentionally NOT exposed here — they require explicit per-action
//! confirmation flows that live with the official ctf2 MCP tools.

use clap::Subcommand;
use serde_json::Value;

#[derive(Subcommand)]
pub enum Ctf2Cmd {
    Whoami,
    Daily { #[arg(long, default_value_t = 20)] limit: usize },
    Practice { #[arg(long, default_value_t = 50)] limit: usize },
    Submissions { #[arg(long, default_value_t = 20)] limit: usize },
    Get { path: String },
}

const BASE: &str = "https://ctf2.dasctf.com/api/open/v1/user";

fn load_token() -> Result<String, String> {
    if let Ok(t) = std::env::var("CTF2_TOKEN") {
        let t = t.trim().to_string();
        if !t.is_empty() {
            return Ok(t);
        }
    }
    for cand in ["api-key.txt", "../api-key.txt"] {
        if let Ok(t) = std::fs::read_to_string(cand) {
            let t = t.trim().to_string();
            if !t.is_empty() {
                return Ok(t);
            }
        }
    }
    Err("no CTF2 token: set $CTF2_TOKEN or provide api-key.txt".into())
}

fn get(path: &str, limit: Option<usize>) -> Result<Value, String> {
    let token = load_token()?;
    let mut url = format!("{BASE}/{}", path.trim_start_matches('/'));
    if let Some(l) = limit {
        url.push_str(&format!("{}limit={l}", if url.contains('?') { "&" } else { "?" }));
    }
    let resp = ureq::get(&url)
        .timeout(std::time::Duration::from_secs(30))
        .set("Authorization", &format!("Bearer {token}"))
        .set("Accept", "application/json")
        .call()
        .map_err(|e| match e {
            ureq::Error::Status(code, resp) => {
                let body = resp.into_string().unwrap_or_default();
                format!("HTTP {code}: {}", body.chars().take(300).collect::<String>())
            }
            other => other.to_string(),
        })?;
    resp.into_json::<Value>().map_err(|e| e.to_string())
}

pub fn run(cmd: Ctf2Cmd) -> ! {
    let result = match cmd {
        Ctf2Cmd::Whoami => get("profile/", None),
        Ctf2Cmd::Daily { limit } => get("daily/", Some(limit)),
        Ctf2Cmd::Practice { limit } => get("practice/", Some(limit)),
        Ctf2Cmd::Submissions { limit } => get("submissions/", Some(limit)),
        Ctf2Cmd::Get { path } => get(&path, None),
    };
    match result {
        Ok(v) => {
            println!("{}", serde_json::to_string_pretty(&v).unwrap());
            std::process::exit(0)
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1)
        }
    }
}

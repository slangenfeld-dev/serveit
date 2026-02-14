use std::{
    net::{IpAddr, SocketAddr},
    path::{Path, PathBuf},
    sync::Arc,
};

use axum::{
    body::Body,
    extract::{Extension as Ext, Multipart, Path as AxumPath},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
    Json, Router,
};
use clap::Parser;

use axum_server::tls_rustls::RustlsConfig;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

use serde::{Deserialize, Serialize};

use tokio::io::AsyncWriteExt;

const MAX_UPLOAD_BYTES: u64 = 50 * 1024 * 1024; // 50 MiB

#[derive(Parser, Debug)]
#[command(name = "lantrix", about = "Serve a directory over HTTP/HTTPS (with directory listings)")]
struct Args {
    /// Interface/IP to bind to (e.g. 127.0.0.1 or 0.0.0.0)
    #[arg(short = 'i', long = "interface", default_value = "127.0.0.1")]
    interface: String,

    /// Port to listen on
    #[arg(short = 'p', long = "port", default_value_t = 8080)]
    port: u16,

    /// Directory to serve (defaults to current working directory)
    #[arg(short = 'd', long = "dir")]
    dir: Option<PathBuf>,

    /// Optional HTTP Basic Auth credentials in the form user:pass
    /// Example: --auth admin:secret
    #[arg(long = "auth")]
    auth: Option<String>,

    /// Serve HTTPS only (self-signed certificate generated at startup)
    #[arg(long = "https")]
    https: bool,

    /// Print the generated certificate PEM to stdout (useful for importing into trust store).
    /// If used with --https, it prints the cert always.
    /// It will also print the private key PEM to stderr.
    #[arg(long = "print-cert")]
    print_cert: bool,

    /// Enable a restricted web console UI at /__console
    #[arg(long = "console")]
    console: bool,
}

#[derive(Clone)]
struct AppState {
    root: PathBuf,            // canonicalized
    auth: Option<AuthConfig>, // parsed credentials
    console: bool,
}

#[derive(Clone)]
struct AuthConfig {
    user: String,
    pass: String,
}

impl AuthConfig {
    fn parse(s: &str) -> Result<Self, &'static str> {
        let (user, pass) = s.split_once(':').ok_or("auth must be in the form user:pass")?;
        if user.is_empty() || pass.is_empty() {
            return Err("auth user and pass must be non-empty");
        }
        Ok(Self {
            user: user.to_string(),
            pass: pass.to_string(),
        })
    }
}

#[tokio::main]
async fn main() {
    if let Err(e) = run().await {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), Box<dyn std::error::Error>> {
    let args = Args::parse();

    let root = args
        .dir
        .unwrap_or_else(|| std::env::current_dir().expect("failed to get current directory"))
        .canonicalize()
        .unwrap_or_else(|e| panic!("cannot canonicalize dir: {e}"));

    let auth = match args.auth.as_deref() {
        Some(s) => Some(AuthConfig::parse(s).unwrap_or_else(|e| panic!("{e}"))),
        None => None,
    };

    let addr: SocketAddr = format!("{}:{}", args.interface, args.port)
        .parse()
        .map_err(|_| "invalid interface/port")?;

    println!("Serving: {}", root.display());
    println!(
        "Auth: {}",
        if auth.is_some() { "enabled" } else { "disabled" }
    );
    println!(
        "Console: {}",
        if args.console { "enabled (/__console)" } else { "disabled" }
    );

    let state = Arc::new(AppState {
        root,
        auth,
        console: args.console,
    });

    let mut app = Router::new()
        .route("/", get(serve_root))
        .route("/*path", get(serve_path));

    if args.console {
        app = app
            .route("/__console", get(console_page))
            .route("/__console/api", post(console_api))
            .route("/__console/upload", post(console_upload)); // <-- NEW
    }

    // IMPORTANT: use axum::Extension (layer type)
    app = app.layer(axum::Extension(state.clone()));

    if args.https {
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );

        let (tls, cert_pem, key_pem) = generate_self_signed_tls_with_pem(&args.interface).await?;

        if args.print_cert {
            print!("{cert_pem}");
            eprintln!("{key_pem}");
        }

        println!("Listening on: https://{addr}");
        println!(
            "Tip: open https://localhost:{} (or https://127.0.0.1:{})",
            args.port, args.port
        );

        axum_server::bind_rustls(addr, tls)
            .serve(app.into_make_service())
            .await?;

        Ok(())
    } else {
        if args.print_cert {
            eprintln!("--print-cert only makes sense with --https (no cert is generated for HTTP).");
        }

        println!("Listening on: http://{addr}");

        let listener = tokio::net::TcpListener::bind(addr)
            .await
            .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));

        axum::serve(listener, app).await?;
        Ok(())
    }
}

async fn generate_self_signed_tls_with_pem(
    interface: &str,
) -> Result<(RustlsConfig, String, String), Box<dyn std::error::Error>> {
    use rcgen::{CertificateParams, DistinguishedName, DnType, SanType};

    let mut params = CertificateParams::new(vec!["localhost".to_string()])?;

    let mut dn = DistinguishedName::new();
    dn.push(DnType::CommonName, "lantrix");
    params.distinguished_name = dn;

    params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::from([127, 0, 0, 1])));

    if let Ok(ip) = interface.parse::<IpAddr>() {
        if !ip.is_unspecified() {
            params.subject_alt_names.push(SanType::IpAddress(ip));
        }
    }

    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let tls = RustlsConfig::from_pem(
        cert_pem.clone().into_bytes(),
        key_pem.clone().into_bytes(),
    )
    .await?;

    Ok((tls, cert_pem, key_pem))
}

async fn serve_root(Ext(state): Ext<Arc<AppState>>, headers: HeaderMap) -> Response {
    serve_rel_path(state, headers, "").await
}

async fn serve_path(
    Ext(state): Ext<Arc<AppState>>,
    headers: HeaderMap,
    AxumPath(path): AxumPath<String>,
) -> Response {
    serve_rel_path(state, headers, &path).await
}

async fn serve_rel_path(state: Arc<AppState>, headers: HeaderMap, rel: &str) -> Response {
    if let Some(cfg) = &state.auth {
        if !is_authorized(&headers, cfg) {
            return unauthorized();
        }
    }

    if !state.console && (rel.starts_with("__console") || rel.starts_with("/__console")) {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    }

    let decoded = match urlencoding::decode(rel) {
        Ok(s) => s.into_owned(),
        Err(_) => return (StatusCode::BAD_REQUEST, "Bad URL encoding").into_response(),
    };

    let candidate = state.root.join(&decoded);

    let meta = match tokio::fs::metadata(&candidate).await {
        Ok(m) => m,
        Err(_) => return (StatusCode::NOT_FOUND, "Not found").into_response(),
    };

    let canon = match tokio::fs::canonicalize(&candidate).await {
        Ok(p) => p,
        Err(_) => return (StatusCode::FORBIDDEN, "Forbidden").into_response(),
    };

    if !canon.starts_with(&state.root) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    if meta.is_dir() {
        if let Some(index) = find_index_file(&canon).await {
            return serve_file(&index).await;
        }
        return list_dir(&state.root, &canon, state.console).await;
    }

    serve_file(&canon).await
}

fn is_authorized(headers: &HeaderMap, cfg: &AuthConfig) -> bool {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return false;
    };
    let Ok(s) = value.to_str() else {
        return false;
    };
    let Some(b64) = s.strip_prefix("Basic ") else {
        return false;
    };

    let Ok(decoded) = B64.decode(b64) else {
        return false;
    };
    let Ok(decoded) = String::from_utf8(decoded) else {
        return false;
    };

    decoded == format!("{}:{}", cfg.user, cfg.pass)
}

fn unauthorized() -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, r#"Basic realm="lantrix""#)
        .body(Body::from("Unauthorized"))
        .unwrap()
}

async fn find_index_file(dir: &Path) -> Option<PathBuf> {
    for name in ["index.html", "index.htm"] {
        let p = dir.join(name);
        if tokio::fs::metadata(&p).await.ok()?.is_file() {
            return Some(p);
        }
    }
    None
}

async fn serve_file(path: &Path) -> Response {
    match tokio::fs::read(path).await {
        Ok(bytes) => {
            let mime = mime_guess::from_path(path).first_or_octet_stream();
            Response::builder()
                .status(StatusCode::OK)
                .header(header::CONTENT_TYPE, mime.as_ref())
                .body(Body::from(bytes))
                .unwrap()
        }
        Err(_) => (StatusCode::FORBIDDEN, "Cannot read file").into_response(),
    }
}

async fn list_dir(root: &Path, dir: &Path, console_enabled: bool) -> Response {
    let mut rd = match tokio::fs::read_dir(dir).await {
        Ok(r) => r,
        Err(_) => return (StatusCode::FORBIDDEN, "Cannot read directory").into_response(),
    };

    let mut items = Vec::new();
    while let Ok(Some(e)) = rd.next_entry().await {
        let name = e.file_name().to_string_lossy().to_string();
        let is_dir = e.file_type().await.map(|t| t.is_dir()).unwrap_or(false);
        items.push((name, is_dir));
    }
    items.sort_by(|a, b| a.0.cmp(&b.0));

    let mut html = String::new();
    html.push_str("<!doctype html><html><head><meta charset='utf-8'>");
    html.push_str("<title>Lantrix</title></head><body>");
    html.push_str(&format!(
        "<h1>Index of {}</h1><ul>",
        display_rel(root, dir)
    ));

    if dir != root {
        html.push_str("<li><a href=\"../\">../</a></li>");
    }

    if console_enabled {
        html.push_str("<li><a href=\"/__console\">__console</a></li>");
    }

    for (name, is_dir) in items {
        let display = if is_dir { format!("{}/", name) } else { name.clone() };
        let href = if is_dir {
            format!("{}{}", urlencoding::encode(&name), "/")
        } else {
            urlencoding::encode(&name).to_string()
        };
        html.push_str(&format!(
            "<li><a href=\"{href}\">{}</a></li>",
            html_escape(&display)
        ));
    }

    html.push_str("</ul></body></html>");
    (StatusCode::OK, Html(html)).into_response()
}

fn display_rel(root: &Path, dir: &Path) -> String {
    match dir.strip_prefix(root) {
        Ok(p) if p.as_os_str().is_empty() => "/".to_string(),
        Ok(p) => format!("/{}", p.to_string_lossy()),
        Err(_) => "/".to_string(),
    }
}

fn html_escape(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
        .replace('\'', "&#39;")
}

/* -------------------------
   Restricted Web Console
   ------------------------- */

async fn console_page(Ext(state): Ext<Arc<AppState>>, headers: HeaderMap) -> Response {
    if let Some(cfg) = &state.auth {
        if !is_authorized(&headers, cfg) {
            return unauthorized();
        }
    }
    if !state.console {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    }

    let html = r#"<!doctype html>
<html>
<head>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1"/>
  <title>Lantrix Console</title>
  <style>
    body { margin: 0; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", "Courier New", monospace; }
    .wrap { padding: 16px; }
    .term { background:#0b1020; color:#e6e6e6; border-radius:10px; padding:14px; min-height:60vh; box-shadow: 0 10px 30px rgba(0,0,0,.25); }
    .out { white-space: pre-wrap; line-height: 1.35; }
    .row { display:flex; gap:10px; margin-top:12px; }
    input { flex:1; background:#141a33; color:#e6e6e6; border:1px solid #2a335e; border-radius:8px; padding:10px; outline:none; }
    button { background:#20C997; border:none; border-radius:8px; padding:10px 14px; font-weight:700; cursor:pointer; }
    .hint { opacity:.8; margin-top:10px; }
    a { color:#20C997; text-decoration:none; }
    .upload { display:flex; gap:10px; margin-top:14px; align-items:center; flex-wrap:wrap; }
    .upload input[type="file"] { color:#e6e6e6; }
    .small { opacity:.85; font-size: 12px; }
  </style>
</head>
<body>
<div class="wrap">
  <div class="term">
    <div class="out" id="out"></div>

    <div class="row">
      <input id="in" placeholder="help | pwd | ls [path] | cat <file>" autocomplete="off"/>
      <button id="run">Run</button>
    </div>

    <div class="upload">
      <input id="file" type="file" />
      <input id="dest" placeholder="upload dir (relative to root), e.g. . or sub/folder" />
      <button id="up">Upload</button>
      <span class="small" id="upmsg"></span>
    </div>

    <div class="hint">Restricted console (read-only + upload). Back to <a href="/">/</a></div>
  </div>
</div>

<script>
const out = document.getElementById('out');
const inp = document.getElementById('in');
const run = document.getElementById('run');
const file = document.getElementById('file');
const dest = document.getElementById('dest');
const up = document.getElementById('up');
const upmsg = document.getElementById('upmsg');

function printLine(s){ out.textContent += s + "\n"; out.scrollTop = out.scrollHeight; }

async function execCmd(line){
  const trimmed = line.trim();
  if(!trimmed) return;
  printLine("> " + trimmed);
  inp.value = "";

  const parts = trimmed.split(/\s+/);
  const cmd = parts[0];
  const arg = parts.slice(1).join(" ");

  const res = await fetch("/__console/api", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ cmd, arg })
  });

  const data = await res.json().catch(() => ({ ok:false, out:"Bad response" }));
  printLine(data.out || "");
}

async function uploadFile(){
  if(!file.files || file.files.length === 0){
    upmsg.textContent = "Pick a file first.";
    return;
  }
  upmsg.textContent = "Uploading...";
  const fd = new FormData();
  fd.append("dir", dest.value || ".");
  fd.append("file", file.files[0]);

  const res = await fetch("/__console/upload", { method:"POST", body: fd });
  const data = await res.json().catch(() => ({ ok:false, out:"Bad response" }));
  upmsg.textContent = data.ok ? "Uploaded." : ("Upload failed: " + (data.out || ""));
  if(data.out) printLine(data.out);
}

run.onclick = () => execCmd(inp.value);
inp.addEventListener('keydown', (e) => { if(e.key === "Enter") execCmd(inp.value); });

up.onclick = () => uploadFile();

printLine("Lantrix console. Type 'help'. Upload below.");
</script>
</body>
</html>
"#;

    (StatusCode::OK, Html(html)).into_response()
}

#[derive(Deserialize)]
struct ConsoleReq {
    cmd: String,
    #[serde(default)]
    arg: String,
}

#[derive(Serialize)]
struct ConsoleResp {
    ok: bool,
    out: String,
}

async fn console_api(
    Ext(state): Ext<Arc<AppState>>,
    headers: HeaderMap,
    Json(req): Json<ConsoleReq>,
) -> Response {
    if let Some(cfg) = &state.auth {
        if !is_authorized(&headers, cfg) {
            return unauthorized();
        }
    }
    if !state.console {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    }

    let cmd = req.cmd.trim().to_lowercase();
    let arg = req.arg.trim().to_string();

    let out = match cmd.as_str() {
        "help" => {
            "Commands:\n  help\n  pwd\n  ls [path]\n  cat <file>\n\nUploads:\n  Use the upload UI below (POST /__console/upload).\n\nAll paths are restricted to the served root.\nNo shell execution."
                .to_string()
        }
        "pwd" => format!("{}", state.root.display()),
        "ls" => {
            let p = if arg.is_empty() {
                state.root.clone()
            } else {
                match safe_join(&state.root, &arg).await {
                    Ok(p) => p,
                    Err(e) => return Json(ConsoleResp { ok: false, out: e }).into_response(),
                }
            };

            match list_dir_plain(&state.root, &p).await {
                Ok(s) => s,
                Err(e) => e,
            }
        }
        "cat" => {
            if arg.is_empty() {
                "Usage: cat <file>".to_string()
            } else {
                match safe_join(&state.root, &arg).await {
                    Ok(p) => match cat_file_limited(&p, 256 * 1024).await {
                        Ok(s) => s,
                        Err(e) => e,
                    },
                    Err(e) => e,
                }
            }
        }
        _ => "Unknown command. Type 'help'.".to_string(),
    };

    Json(ConsoleResp { ok: true, out }).into_response()
}

#[derive(Serialize)]
struct UploadResp {
    ok: bool,
    out: String,
}

// Multipart fields:
// - dir: text, relative destination directory under root (optional, defaults ".")
// - file: file to upload (required)
async fn console_upload(
    Ext(state): Ext<Arc<AppState>>,
    headers: HeaderMap,
    mut mp: Multipart,
) -> Response {
    if let Some(cfg) = &state.auth {
        if !is_authorized(&headers, cfg) {
            return unauthorized();
        }
    }
    if !state.console {
        return (StatusCode::NOT_FOUND, "Not found").into_response();
    }

    let mut dir_rel: String = ".".to_string();
    let mut saved_path: Option<PathBuf> = None;
    let mut total_written: u64 = 0;

    while let Ok(Some(field)) = mp.next_field().await {
        let name = field.name().unwrap_or("").to_string();

        if name == "dir" {
            if let Ok(text) = field.text().await {
                let t = text.trim();
                if !t.is_empty() {
                    dir_rel = t.to_string();
                }
            }
            continue;
        }

        if name == "file" {
            let orig_name = match field.file_name().map(|s| s.to_string()) {
                Some(n) => n,
                None => {
                    return Json(UploadResp {
                        ok: false,
                        out: "Missing filename".into(),
                    })
                    .into_response()
                }
            };

            let file_name = match sanitize_filename(&orig_name) {
                Some(n) => n,
                None => {
                    return Json(UploadResp {
                        ok: false,
                        out: "Bad filename".into(),
                    })
                    .into_response()
                }
            };

            // Ensure target dir is within root and is a directory
            let target_dir = match safe_join_dir(&state.root, &dir_rel).await {
                Ok(p) => p,
                Err(e) => return Json(UploadResp { ok: false, out: e }).into_response(),
            };

            let dest_path = target_dir.join(&file_name);

            // Disallow overwrite by default
            if tokio::fs::metadata(&dest_path).await.is_ok() {
                return Json(UploadResp {
                    ok: false,
                    out: "File already exists (overwrite not allowed)".into(),
                })
                .into_response();
            }

            let mut f = match tokio::fs::File::create(&dest_path).await {
                Ok(x) => x,
                Err(_) => {
                    return Json(UploadResp {
                        ok: false,
                        out: "Cannot create destination file".into(),
                    })
                    .into_response()
                }
            };

            let mut field = field;
            while let Ok(Some(chunk)) = field.chunk().await {
                total_written = total_written.saturating_add(chunk.len() as u64);
                if total_written > MAX_UPLOAD_BYTES {
                    let _ = tokio::fs::remove_file(&dest_path).await;
                    return Json(UploadResp {
                        ok: false,
                        out: format!("Upload too large (max {} bytes)", MAX_UPLOAD_BYTES),
                    })
                    .into_response();
                }

                if f.write_all(&chunk).await.is_err() {
                    let _ = tokio::fs::remove_file(&dest_path).await;
                    return Json(UploadResp {
                        ok: false,
                        out: "Write failed".into(),
                    })
                    .into_response();
                }
            }

            saved_path = Some(dest_path);
        }
    }

    let saved = match saved_path {
        Some(p) => p,
        None => {
            return Json(UploadResp {
                ok: false,
                out: "No file field provided".into(),
            })
            .into_response()
        }
    };

    Json(UploadResp {
        ok: true,
        out: format!("Uploaded to: {}", saved.display()),
    })
    .into_response()
}

// Join + canonicalize + root check (file or directory)
async fn safe_join(root: &Path, rel: &str) -> Result<PathBuf, String> {
    let candidate = root.join(rel);
    let canon = tokio::fs::canonicalize(&candidate)
        .await
        .map_err(|_| "Not found / not accessible".to_string())?;

    if !canon.starts_with(root) {
        return Err("Forbidden (outside root)".to_string());
    }
    Ok(canon)
}

// Like safe_join, but if it doesn't exist yet, verify via parent canonicalization.
// Also ensures the resolved path is a directory.
async fn safe_join_dir(root: &Path, rel: &str) -> Result<PathBuf, String> {
    let rel = rel.trim();
    let rel = if rel.is_empty() { "." } else { rel };

    let candidate = root.join(rel);

    // If dir exists, canonicalize directly
    if let Ok(meta) = tokio::fs::metadata(&candidate).await {
        if !meta.is_dir() {
            return Err("Destination is not a directory".to_string());
        }
        let canon = tokio::fs::canonicalize(&candidate)
            .await
            .map_err(|_| "Not found / not accessible".to_string())?;
        if !canon.starts_with(root) {
            return Err("Forbidden (outside root)".to_string());
        }
        return Ok(canon);
    }

    // If it doesn't exist, canonicalize the parent and then append the final component
    let parent = candidate.parent().ok_or_else(|| "Bad destination".to_string())?;
    let parent_canon = tokio::fs::canonicalize(parent)
        .await
        .map_err(|_| "Destination parent not found".to_string())?;
    if !parent_canon.starts_with(root) {
        return Err("Forbidden (outside root)".to_string());
    }

    Err("Destination directory does not exist".to_string())
}

fn sanitize_filename(name: &str) -> Option<String> {
    // keep only the last path component, reject empty / "." / ".."
    let n = Path::new(name).file_name()?.to_string_lossy().to_string();
    let n = n.trim().to_string();
    if n.is_empty() || n == "." || n == ".." {
        return None;
    }
    // very small hardening: strip path separators if any slipped in
    let n = n.replace('/', "_").replace('\\', "_");
    Some(n)
}

async fn list_dir_plain(root: &Path, dir: &Path) -> Result<String, String> {
    let meta = tokio::fs::metadata(dir)
        .await
        .map_err(|_| "Not found".to_string())?;
    if !meta.is_dir() {
        return Err("Not a directory".to_string());
    }

    let mut rd = tokio::fs::read_dir(dir)
        .await
        .map_err(|_| "Cannot read directory".to_string())?;

    let mut items: Vec<String> = Vec::new();
    while let Ok(Some(e)) = rd.next_entry().await {
        let name = e.file_name().to_string_lossy().to_string();
        let is_dir = e.file_type().await.map(|t| t.is_dir()).unwrap_or(false);
        items.push(if is_dir { format!("{name}/") } else { name });
    }
    items.sort();

    let rel = display_rel(root, dir);
    Ok(format!("{rel}\n{}", items.join("\n")))
}

async fn cat_file_limited(path: &Path, max_bytes: usize) -> Result<String, String> {
    let meta = tokio::fs::metadata(path)
        .await
        .map_err(|_| "Not found".to_string())?;
    if !meta.is_file() {
        return Err("Not a file".to_string());
    }
    if meta.len() as usize > max_bytes {
        return Err(format!("File too large (>{} bytes)", max_bytes));
    }

    let bytes = tokio::fs::read(path)
        .await
        .map_err(|_| "Cannot read file".to_string())?;

    Ok(String::from_utf8_lossy(&bytes).to_string())
}

use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use axum::{
    body::Body,
    extract::{Path as AxumPath, State},
    http::{header, HeaderMap, StatusCode},
    response::{Html, IntoResponse, Response},
    routing::get,
    Router,
};
use clap::Parser;

#[derive(Parser, Debug)]
#[command(name = "serveit", about = "Serve a directory over HTTP (with directory listings)")]
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
}

#[derive(Clone)]
struct AppState {
    root: PathBuf,            // canonicalized
    auth: Option<AuthConfig>, // parsed credentials
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
        .expect("invalid interface/port");

    println!("Serving: {}", root.display());
    println!("Listening on: http://{addr}");
    if auth.is_some() {
        println!("Auth: enabled (HTTP Basic)");
    } else {
        println!("Auth: disabled");
    }

    let app = Router::new()
        .route("/", get(serve_root))
        .route("/*path", get(serve_path))
        .with_state(AppState { root, auth });

    let listener = tokio::net::TcpListener::bind(addr)
        .await
        .unwrap_or_else(|e| panic!("failed to bind {addr}: {e}"));

    axum::serve(listener, app).await.expect("server error");
}

async fn serve_root(State(state): State<AppState>, headers: HeaderMap) -> Response {
    serve_rel_path(state, headers, "").await
}

async fn serve_path(
    State(state): State<AppState>,
    headers: HeaderMap,
    AxumPath(path): AxumPath<String>,
) -> Response {
    serve_rel_path(state, headers, &path).await
}

async fn serve_rel_path(state: AppState, headers: HeaderMap, rel: &str) -> Response {
    // Optional basic auth
    if let Some(cfg) = &state.auth {
        if !is_authorized(&headers, cfg) {
            return unauthorized();
        }
    }

    // URL decode (so "My%20File.txt" works)
    let decoded = match urlencoding::decode(rel) {
        Ok(s) => s.into_owned(),
        Err(_) => return (StatusCode::BAD_REQUEST, "Bad URL encoding").into_response(),
    };

    // Build a candidate path
    let candidate = state.root.join(&decoded);

    // Path traversal protection: canonicalize and ensure it stays under root.
    // Note: canonicalize requires the path to exist, so we do existence check after.
    let meta = match tokio::fs::metadata(&candidate).await {
        Ok(m) => m,
        Err(_) => return (StatusCode::NOT_FOUND, "Not found").into_response(),
    };

    let canon_candidate = match tokio::fs::canonicalize(&candidate).await {
        Ok(p) => p,
        Err(_) => return (StatusCode::FORBIDDEN, "Forbidden").into_response(),
    };

    if !canon_candidate.starts_with(&state.root) {
        return (StatusCode::FORBIDDEN, "Forbidden").into_response();
    }

    if meta.is_dir() {
        // If directory has an index file, serve it
        if let Some(index_path) = find_index_file(&canon_candidate).await {
            return serve_file(&index_path).await;
        }
        // Otherwise list directory
        return list_dir(&state.root, &canon_candidate).await;
    }

    // Serve file
    serve_file(&canon_candidate).await
}

fn is_authorized(headers: &HeaderMap, cfg: &AuthConfig) -> bool {
    let Some(value) = headers.get(header::AUTHORIZATION) else {
        return false;
    };
    let Ok(s) = value.to_str() else { return false; };

    // Expect: "Basic base64(user:pass)"
    let Some(b64) = s.strip_prefix("Basic ") else {
        return false;
    };

    let Ok(decoded_bytes) = base64::decode(b64) else {
        return false;
    };
    let Ok(decoded_str) = String::from_utf8(decoded_bytes) else {
        return false;
    };

    decoded_str == format!("{}:{}", cfg.user, cfg.pass)
}

fn unauthorized() -> Response {
    Response::builder()
        .status(StatusCode::UNAUTHORIZED)
        .header(header::WWW_AUTHENTICATE, r#"Basic realm="serveit""#)
        .body(Body::from("Unauthorized"))
        .unwrap()
}

async fn find_index_file(dir: &Path) -> Option<PathBuf> {
    // Try a few common names (add more if you like)
    let candidates = ["index.html", "index.htm"];
    for name in candidates {
        let p = dir.join(name);
        if tokio::fs::metadata(&p).await.ok().map(|m| m.is_file()).unwrap_or(false) {
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

async fn list_dir(root: &Path, dir: &Path) -> Response {
    let mut entries = match tokio::fs::read_dir(dir).await {
        Ok(rd) => rd,
        Err(_) => return (StatusCode::FORBIDDEN, "Cannot read directory").into_response(),
    };

    let mut items: Vec<(String, bool)> = Vec::new();
    while let Ok(Some(e)) = entries.next_entry().await {
        let name = e.file_name().to_string_lossy().to_string();
        let is_dir = e.file_type().await.map(|t| t.is_dir()).unwrap_or(false);
        items.push((name, is_dir));
    }
    items.sort_by(|a, b| a.0.cmp(&b.0));

    let mut html = String::new();
    html.push_str("<!doctype html><html><head><meta charset='utf-8'>");
    html.push_str("<title>Index</title>");
    html.push_str("<style>body{font-family:system-ui,Arial,sans-serif} a{text-decoration:none}</style>");
    html.push_str("</head><body>");
    html.push_str(&format!(
        "<h1>Index of {}</h1><ul>",
        html_escape(&display_rel(root, dir))
    ));

    if dir != root {
        html.push_str("<li><a href=\"../\">../</a></li>");
    }

    for (name, is_dir) in items {
        let display = if is_dir { format!("{}/", name) } else { name.clone() };
        let href = if is_dir {
            format!("{}{}", urlencoding::encode(&name), "/")
        } else {
            urlencoding::encode(&name).to_string()
        };

        html.push_str(&format!(
            "<li><a href=\"{href}\">{text}</a></li>",
            href = href,
            text = html_escape(&display)
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

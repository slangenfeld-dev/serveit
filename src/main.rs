use std::{
    net::{IpAddr, SocketAddr},
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

use axum_server::tls_rustls::RustlsConfig;

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine as _;

#[derive(Parser, Debug)]
#[command(name = "serveit", about = "Serve a directory over HTTP/HTTPS (with directory listings)")]
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

    let app = Router::new()
        .route("/", get(serve_root))
        .route("/*path", get(serve_path))
        .with_state(AppState { root, auth });

    if args.https {
        // Install the rustls CryptoProvider (ring backend) to avoid panic
        let _ = rustls::crypto::CryptoProvider::install_default(
            rustls::crypto::ring::default_provider(),
        );

        let (tls, cert_pem, key_pem) =
            generate_self_signed_tls_with_pem(&args.interface).await?;

        if args.print_cert {
            // Cert to stdout (safe-ish), key to stderr (keep out of logs if you redirect stdout)
            print!("{cert_pem}");
            eprintln!("{key_pem}");
        }

        println!("Listening on: https://{addr}");
        println!("Tip: open https://localhost:{} (or https://127.0.0.1:{})", args.port, args.port);

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
    dn.push(DnType::CommonName, "serveit");
    params.distinguished_name = dn;

    // Allow https://127.0.0.1
    params
        .subject_alt_names
        .push(SanType::IpAddress(IpAddr::from([127, 0, 0, 1])));

    // If binding to a concrete IP (e.g. 192.168.1.10), include it in SAN.
    // If it's 0.0.0.0 / :: (bind-any), skip it (you don't browse to 0.0.0.0).
    if let Ok(ip) = interface.parse::<IpAddr>() {
        if !ip.is_unspecified() {
            params.subject_alt_names.push(SanType::IpAddress(ip));
        }
    }

    // rcgen 0.13 API: KeyPair + self_signed
    let key_pair = rcgen::KeyPair::generate()?;
    let cert = params.self_signed(&key_pair)?;

    let cert_pem = cert.pem();
    let key_pem = key_pair.serialize_pem();

    let tls = RustlsConfig::from_pem(cert_pem.clone().into_bytes(), key_pem.clone().into_bytes()).await?;
    Ok((tls, cert_pem, key_pem))
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
    if let Some(cfg) = &state.auth {
        if !is_authorized(&headers, cfg) {
            return unauthorized();
        }
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
        return list_dir(&state.root, &canon).await;
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
        .header(header::WWW_AUTHENTICATE, r#"Basic realm="serveit""#)
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

async fn list_dir(root: &Path, dir: &Path) -> Response {
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
    html.push_str("<title>Index</title></head><body>");
    html.push_str(&format!(
        "<h1>Index of {}</h1><ul>",
        display_rel(root, dir)
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

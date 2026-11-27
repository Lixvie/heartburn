//! Standalone debugging and local testing CLI for `heartburn-core`.
//!
//! Running `heartburn` with no arguments prints usage/help and exits with status 0
//! without touching any OS network or proxy settings.

use std::future::Future;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use base64::Engine as _;
use clap::{CommandFactory, Parser, Subcommand};
use heartburn_core::challenge::CaptchaSolver;
use heartburn_core::config::Config;
use heartburn_core::error::FxaError;
use heartburn_core::fxa::{FXA_ERRNO_REQUEST_BLOCKED, SignInStep};
use heartburn_core::storage::{FsStorage, Storage};
use heartburn_core::{EngineState, HeartburnEngine};
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
#[command(
    name = "heartburn",
    version,
    about = "Standalone debugging CLI for heartburn proxy engine (sing-box upstream)"
)]
struct Cli {
    /// Directory containing config.json, credentials.json, and caches.
    #[arg(long, global = true, default_value = "user-data")]
    data_dir: PathBuf,

    /// Enable verbose diagnostic logging.
    #[arg(short, long, global = true)]
    verbose: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Run the local SOCKS5/HTTP proxy listener in the foreground until Ctrl+C.
    Run {
        /// Override local listen address (e.g. 127.0.0.1:10810).
        #[arg(long)]
        listen: Option<String>,

        /// Override proxy exit country code/name (or "fastest").
        #[arg(long)]
        country: Option<String>,

        /// Override upstream transport ("h2", "h3", or "h1").
        #[arg(long)]
        transport: Option<String>,
    },

    /// Validate config.json in `--data-dir` (creating default if missing).
    ValidateConfig,

    /// Sign in with a Firefox Account and save credentials to `--data-dir`.
    Login {
        #[arg(long)]
        email: String,
        #[arg(long)]
        password: Option<String>,
        #[arg(long)]
        unblock_code: Option<String>,
    },

    /// List configured accounts in `--data-dir`.
    Accounts {
        /// Probe Guardian HEAD /api/v1/fpn/token for live quota metrics.
        #[arg(long)]
        check_quota: bool,
    },

    /// Remove an account ID from `--data-dir`.
    RemoveAccount { id: String },

    /// Print persisted status.json and active config summary.
    Status,
}

fn init_logging(verbose: bool) {
    let default_level = if verbose {
        "heartburn=debug,heartburn_core=debug,info"
    } else {
        "heartburn=info,heartburn_core=info,warn"
    };
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(default_level));
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_target(true)
        .try_init();
}

#[tokio::main]
async fn main() -> ExitCode {
    if std::env::args_os().len() <= 1 {
        let mut cmd = Cli::command();
        let _ = cmd.print_help();
        println!();
        return ExitCode::SUCCESS;
    }

    let cli = Cli::parse();
    init_logging(cli.verbose);

    let Some(command) = cli.command else {
        let mut cmd = Cli::command();
        let _ = cmd.print_help();
        println!();
        return ExitCode::SUCCESS;
    };

    match run_command(cli.data_dir, cli.verbose, command).await {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            eprintln!("error: {err}");
            ExitCode::FAILURE
        }
    }
}

async fn run_command(
    data_dir: PathBuf,
    verbose: bool,
    cmd: Commands,
) -> Result<(), Box<dyn std::error::Error>> {
    Box::pin(async move {
        tracing::debug!(
            data_dir = %data_dir.display(),
            command = ?cmd,
            tls_backend = heartburn_core::tls::tls_backend_name(),
            "executing heartburn CLI command"
        );
        match cmd {
            Commands::ValidateConfig => cmd_validate_config(data_dir).await,
            Commands::Run {
                listen,
                country,
                transport,
            } => cmd_run(data_dir, verbose, listen, country, transport).await,
            Commands::Login {
                email,
                password,
                unblock_code,
            } => cmd_login(data_dir, email, password, unblock_code).await,
            Commands::Accounts { check_quota } => cmd_accounts(data_dir, check_quota).await,
            Commands::RemoveAccount { id } => cmd_remove_account(data_dir, id).await,
            Commands::Status => cmd_status(data_dir).await,
        }
    })
    .await
}

async fn cmd_validate_config(data_dir: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    Box::pin(async move {
        let storage = FsStorage::new(&data_dir);
        let (cfg, created) = Config::load_from(&storage).await?;
        cfg.validate()?;
        println!(
            "config valid ({}; listen={}, transport={}, servers={})",
            if created { "created default" } else { "loaded" },
            cfg.proxy.listen,
            cfg.proxy.transport,
            cfg.dns.servers.len()
        );
        Ok(())
    })
    .await
}

async fn cmd_run(
    data_dir: PathBuf,
    verbose: bool,
    listen: Option<String>,
    country: Option<String>,
    transport: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    Box::pin(async move {
        let engine = HeartburnEngine::with_data_dir(&data_dir, None).await?;
        let mut cfg = engine.config().await;
        let mut changed = false;
        if let Some(l) = listen {
            cfg.proxy.listen = l;
            changed = true;
        }
        if let Some(c) = country {
            cfg.proxy.country = c;
            cfg.proxy.server.clear();
            changed = true;
        }
        if let Some(t) = transport {
            cfg.proxy.transport = t;
            changed = true;
        }
        if verbose && !cfg.logging.verbose {
            cfg.logging.verbose = true;
            changed = true;
        }
        if changed {
            engine.update_config(cfg).await?;
        }

        let mut events = engine.subscribe_events();
        let ev_task = tokio::spawn(async move {
            while let Ok(ev) = events.recv().await {
                tracing::info!(event = ?ev, "engine event");
            }
        });

        engine.start().await?;
        let st = engine.status();
        tracing::debug!(
            tls_backend = heartburn_core::tls::tls_backend_name(),
            listen_addr = %st.listen_addr,
            server = %st.server,
            transport = %st.transport,
            "proxy listener active"
        );
        println!(
            "heartburn listening on {} via {} ({})",
            st.listen_addr, st.server, st.transport
        );

        let _ = tokio::signal::ctrl_c().await;
        println!("shutting down cleanly...");
        let _ = engine.stop().await;
        ev_task.abort();
        assert_eq!(engine.status().state, EngineState::Stopped);
        Ok(())
    })
    .await
}

#[derive(Debug)]
struct CliCaptchaSolver;

struct TempCaptchaFile(PathBuf);

impl Drop for TempCaptchaFile {
    fn drop(&mut self) {
        if let Err(err) = std::fs::remove_file(&self.0)
            && err.kind() != io::ErrorKind::NotFound
        {
            tracing::debug!(path = %self.0.display(), error = %err, "failed removing temporary CAPTCHA file");
        }
    }
}

impl CaptchaSolver for CliCaptchaSolver {
    fn solve_captcha<'a>(
        &'a self,
        image_data_url: &'a str,
    ) -> Pin<Box<dyn Future<Output = Result<String, FxaError>> + Send + 'a>> {
        let data_url = image_data_url.to_owned();
        Box::pin(async move {
            tokio::task::spawn_blocking(move || solve_captcha_blocking(&data_url))
                .await
                .map_err(|e| FxaError::ChallengeBlocked(format!("CAPTCHA task failed: {e}")))?
        })
    }
}

fn solve_captcha_blocking(image_data_url: &str) -> Result<String, FxaError> {
    static NEXT_ID: AtomicU64 = AtomicU64::new(1);

    let (ext, bytes) =
        decode_data_url_image(image_data_url).map_err(FxaError::ChallengeBlocked)?;
    let seq = NEXT_ID.fetch_add(1, Ordering::Relaxed);
    let file_name = format!("heartburn-captcha-{}-{seq}.{ext}", std::process::id());
    let path = std::env::temp_dir().join(file_name);

    std::fs::write(&path, &bytes).map_err(|e| {
        FxaError::ChallengeBlocked(format!(
            "failed writing CAPTCHA image {}: {e}",
            path.display()
        ))
    })?;
    let _cleanup = TempCaptchaFile(path.clone());

    println!("\nFastly requires an interactive CAPTCHA challenge.");
    println!("CAPTCHA image saved to: {}", path.display());
    if !try_open_image_viewer(&path) {
        println!("Could not open image automatically; please open the file above manually.");
    }

    for attempt in 0..3 {
        let answer = prompt_line("Enter CAPTCHA text: ")
            .map_err(|e| FxaError::ChallengeBlocked(format!("reading CAPTCHA input: {e}")))?;
        if !answer.is_empty() {
            return Ok(answer);
        }
        if attempt < 2 {
            println!("CAPTCHA input was empty; please type the characters shown in the image.");
        }
    }

    Err(FxaError::ChallengeBlocked("empty CAPTCHA solution entered".into()))
}

fn decode_data_url_image(data_url: &str) -> Result<(&'static str, Vec<u8>), String> {
    let (meta, payload) = data_url
        .trim()
        .split_once(',')
        .ok_or_else(|| "invalid CAPTCHA data URL (missing comma)".to_owned())?;
    let mime_part = meta
        .strip_prefix("data:image/")
        .ok_or_else(|| "CAPTCHA payload is not a data:image/ URL".to_owned())?;
    let subtype = mime_part.split([';', '+']).next().unwrap_or("png").trim();
    let ext = match subtype.to_ascii_lowercase().as_str() {
        "png" => "png",
        "jpeg" | "jpg" => "jpg",
        "webp" => "webp",
        "gif" => "gif",
        "bmp" => "bmp",
        "svg" => "svg",
        _ => "png",
    };

    let clean_b64: String = payload.chars().filter(|c| !c.is_whitespace()).collect();
    let bytes = base64::engine::general_purpose::STANDARD
        .decode(clean_b64)
        .map_err(|e| format!("failed decoding base64 CAPTCHA image: {e}"))?;
    if bytes.is_empty() {
        return Err("decoded CAPTCHA image is empty".into());
    }
    Ok((ext, bytes))
}

fn try_open_image_viewer(path: &Path) -> bool {
    #[cfg(target_os = "windows")]
    {
        std::process::Command::new("cmd")
            .args(["/C", "start", ""])
            .arg(path)
            .spawn()
            .is_ok()
    }
    #[cfg(target_os = "macos")]
    {
        std::process::Command::new("open").arg(path).spawn().is_ok()
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        std::process::Command::new("xdg-open").arg(path).spawn().is_ok()
    }
}

async fn cmd_login(
    data_dir: PathBuf,
    email: String,
    password: Option<String>,
    unblock_code: Option<String>,
) -> Result<(), Box<dyn std::error::Error>> {
    Box::pin(async move {
        let engine = HeartburnEngine::with_data_dir(&data_dir, None).await?;
        engine.set_captcha_solver(Some(Arc::new(CliCaptchaSolver)));

        let pw = match password {
            Some(p) => p,
            None => prompt_line("Password: ")?,
        };

        let mut step_res = engine
            .login_fxa(&email, &pw, unblock_code.as_deref())
            .await;

        for attempt in 0..3 {
            match &step_res {
                Err(FxaError::Api {
                    errno: FXA_ERRNO_REQUEST_BLOCKED,
                    ..
                }) => {
                    if attempt == 0 {
                        println!(
                            "Sign-in blocked as unusual (errno 125). Requesting an unblock code email for {email}..."
                        );
                        engine.fxa_client().send_unblock_code(&email).await?;
                    } else {
                        println!(
                            "That unblock code was not accepted. Check the latest email from Mozilla and try again."
                        );
                    }
                    let code = prompt_line("Unblock code: ")?;
                    step_res = engine.login_fxa(&email, &pw, Some(&code)).await;
                }
                _ => break,
            }
        }

        let step = step_res?;
        let session = match step {
            SignInStep::Verified(s) => s,
            SignInStep::NeedsVerification { session, method } => {
                let effective_email = session.email.as_deref().unwrap_or(&email);
                verify_fxa_session_interactive(&engine, effective_email, &session.session_token, &method)
                    .await?;
                session
            }
        };

        let effective_email = session.email.as_deref().unwrap_or(&email);
        let creds = engine
            .complete_account_onboarding(effective_email, &pw, &session.uid, &session.session_token)
            .await?;
        println!("saved account {} ({})", creds.email, creds.id);
        Ok(())
    })
    .await
}

async fn verify_fxa_session_interactive(
    engine: &HeartburnEngine,
    email: &str,
    session_token: &str,
    method: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    Box::pin(async move {
        if method == "email" {
            println!("This sign-in requires confirmation: an approval link was sent to {email}.");
            for _ in 0..5 {
                let _ = prompt_line("Open the confirmation link from your email, then press Enter to continue: ")?;
                if engine.fxa_client().session_status(session_token).await? {
                    println!("Session verified.");
                    return Ok(());
                }
                println!("Session is not verified yet.");
            }
            return Err("email confirmation link was not completed".into());
        }

        if method.contains("totp") {
            println!("Two-factor authentication required ({method}).");
            for _ in 0..5 {
                let code = prompt_line("Authenticator 6-digit code: ")?;
                if code.is_empty() {
                    continue;
                }
                match engine.fxa_client().verify_totp(session_token, &code).await {
                    Ok(true) => {
                        println!("Session verified.");
                        return Ok(());
                    }
                    Ok(false) => println!("Authenticator code was not accepted; try again."),
                    Err(err) => println!("TOTP verification failed: {err}"),
                }
            }
            return Err("too many failed authenticator verification attempts".into());
        }

        println!("Sign-in verification required ({method}): check {email} for a verification code.");
        for _ in 0..5 {
            let code = prompt_line("Email verification code (or type 'resend'): ")?;
            if code.is_empty() {
                continue;
            }
            if code.eq_ignore_ascii_case("resend") {
                engine.fxa_client().resend_email_code(session_token).await?;
                println!("Verification email resent to {email}.");
                continue;
            }
            match engine
                .fxa_client()
                .verify_email_code(session_token, &code)
                .await
            {
                Ok(()) => {
                    println!("Session verified.");
                    return Ok(());
                }
                Err(err) => println!("Verification failed: {err}"),
            }
        }
        Err("too many failed email verification attempts".into())
    })
    .await
}

async fn cmd_accounts(
    data_dir: PathBuf,
    check_quota: bool,
) -> Result<(), Box<dyn std::error::Error>> {
    Box::pin(async move {
        let engine = HeartburnEngine::with_data_dir(&data_dir, None).await?;
        let list = engine.list_accounts().await;
        if list.is_empty() {
            println!("no accounts configured in {}", data_dir.display());
            return Ok(());
        }
        for slot in list {
            let usage = if check_quota {
                engine.check_account_quota(&slot.creds.id).await.ok()
            } else {
                slot.usage.clone()
            };
            match usage {
                Some(u) => println!(
                    "{}  {}  enabled={}  exhausted={}  used={:.1}% ({} / {} bytes)",
                    slot.creds.id,
                    slot.creds.email,
                    slot.enabled,
                    slot.exhausted,
                    u.used_percent(),
                    u.used_bytes,
                    u.limit_bytes
                ),
                None => println!(
                    "{}  {}  enabled={}  exhausted={}  quota=unknown",
                    slot.creds.id, slot.creds.email, slot.enabled, slot.exhausted
                ),
            }
        }
        Ok(())
    })
    .await
}

async fn cmd_remove_account(
    data_dir: PathBuf,
    id: String,
) -> Result<(), Box<dyn std::error::Error>> {
    Box::pin(async move {
        let engine = HeartburnEngine::with_data_dir(&data_dir, None).await?;
        let removed = engine.remove_account(&id).await?;
        println!(
            "{}",
            if removed {
                format!("removed account {id}")
            } else {
                format!("account {id} not found")
            }
        );
        Ok(())
    })
    .await
}

async fn cmd_status(data_dir: PathBuf) -> Result<(), Box<dyn std::error::Error>> {
    Box::pin(async move {
        let storage = FsStorage::new(&data_dir);
        let cfg_bytes = storage.read("config.json").await?;
        let status_bytes = storage.read("status.json").await?;
        if let Some(raw) = status_bytes {
            println!("{}", String::from_utf8_lossy(&raw));
        } else if let Some(raw) = cfg_bytes {
            println!(
                "engine stopped (no status.json yet); config.json:\n{}",
                String::from_utf8_lossy(&raw)
            );
        } else {
            println!("empty data directory: {}", data_dir.display());
        }
        Ok(())
    })
    .await
}

fn prompt_line(label: &str) -> Result<String, io::Error> {
    print!("{label}");
    io::stdout().flush()?;
    let mut line = String::new();
    io::stdin().read_line(&mut line)?;
    Ok(line.trim().to_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cli_help_renders_without_mutating_network() {
        let mut cmd = Cli::command();
        let mut out = Vec::new();
        cmd.write_help(&mut out).unwrap();
        let help = String::from_utf8(out).unwrap();
        assert!(help.contains("heartburn"));
        assert!(help.contains("validate-config"));
    }

    #[test]
    fn decodes_captcha_data_urls_with_expected_extension() {
        let png_b64 = base64::engine::general_purpose::STANDARD.encode(b"\x89PNG\r\n\x1a\n");
        let (ext, bytes) =
            decode_data_url_image(&format!("data:image/png;base64,{png_b64}")).unwrap();
        assert_eq!(ext, "png");
        assert_eq!(bytes, b"\x89PNG\r\n\x1a\n");

        let jpg_b64 = base64::engine::general_purpose::STANDARD.encode(b"jpeg-bytes");
        let (ext2, bytes2) =
            decode_data_url_image(&format!("data:image/jpeg;base64,{jpg_b64}")).unwrap();
        assert_eq!(ext2, "jpg");
        assert_eq!(bytes2, b"jpeg-bytes");

        assert!(decode_data_url_image("https://example.com/captcha.png").is_err());
        assert!(decode_data_url_image("data:image/png;base64,").is_err());
    }
}

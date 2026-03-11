use crate::config::AppConfig;
use crate::credentials;
use colored::Colorize;
use std::io::{BufRead, BufReader, Write};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::SystemTime;
use tempfile::NamedTempFile;
use totp_rs::TOTP;
use zeroize::Zeroizing;

/// Connect to a VPN using saved credentials.
pub fn connect(config_name: &str, extra_args: &[String], verbose: bool) -> Result<(), Box<dyn std::error::Error>> {
    let openvpn = find_openvpn()?;

    // Load config to get the .ovpn file path
    let app_config = AppConfig::load()?;
    let vpn_config = app_config
        .configs
        .get(config_name)
        .ok_or_else(|| format!("No saved config for '{}'. Run 'save-auth {}' first.", config_name, config_name))?;

    // Retrieve credentials
    let (username, password, otp) = credentials::get_credentials(config_name)?;

    // Build the password string (password + generated TOTP code if present)
    let auth_password = if let Some(ref otp_val) = otp {
        let totp_code = generate_totp(otp_val.as_str())?;
        if verbose {
            println!("  {} TOTP code generated successfully", "✓".green());
        }
        Zeroizing::new(format!("{}{}", password.as_str(), totp_code))
    } else {
        password
    };

    // Create a temporary auth file for --auth-user-pass
    // Use into_temp_path() to close the file handle before OpenVPN reads it.
    let mut auth_file = NamedTempFile::new()?;
    writeln!(auth_file, "{}", username)?;
    writeln!(auth_file, "{}", auth_password.as_str())?;
    auth_file.flush()?;

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = auth_file.as_file().metadata()?.permissions();
        perms.set_mode(0o600);
        auth_file.as_file().set_permissions(perms)?;
    }

    let auth_temp_path = auth_file.into_temp_path();
    let auth_path = auth_temp_path.to_string_lossy().to_string();

    println!(
        "{} {} {}",
        "⟩".bold().cyan(),
        "Connecting to".bold(),
        config_name.bold().cyan()
    );

    // Catch Ctrl+C so the wrapper doesn't die before OpenVPN cleans up.
    let shutdown = Arc::new(AtomicBool::new(false));
    {
        let shutdown = Arc::clone(&shutdown);
        ctrlc::set_handler(move || {
            shutdown.store(true, Ordering::SeqCst);
        })
        .ok();
    }

    // Build command
    let mut cmd = Command::new(&openvpn);
    cmd.arg("--config")
        .arg(&vpn_config.ovpn_file)
        .arg("--auth-user-pass")
        .arg(&auth_path);

    // Add any extra args
    for arg in extra_args {
        cmd.arg(arg);
    }

    if verbose {
        // Verbose mode: stream all output directly
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::inherit())
            .stderr(Stdio::inherit());

        let mut child = cmd.spawn()?;
        let status = child.wait()?;

        if shutdown.load(Ordering::SeqCst) {
            println!();
            print_status("⏏", "Disconnected", "cyan");
        } else if !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
    } else {
        // Clean mode: capture ALL output and show only key events
        cmd.stdin(Stdio::inherit())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());

        let mut child = cmd.spawn()?;

        let stderr = child.stderr.take();
        let stdout = child.stdout.take();

        // Merge both streams into a single channel
        let (tx, rx) = std::sync::mpsc::channel::<String>();

        let tx_out = tx.clone();
        let stdout_handle = std::thread::spawn(move || {
            if let Some(out) = stdout {
                let reader = BufReader::new(out);
                for line in reader.lines().flatten() {
                    let _ = tx_out.send(line);
                }
            }
        });

        let tx_err = tx;
        let stderr_handle = std::thread::spawn(move || {
            if let Some(err) = stderr {
                let reader = BufReader::new(err);
                for line in reader.lines().flatten() {
                    let _ = tx_err.send(line);
                }
            }
        });

        let mut connected = false;

        for line in rx {
            let msg = strip_timestamp(&line);

            if msg.contains("Peer Connection Initiated") {
                print_status("🔑", "TLS handshake complete", "yellow");
            } else if msg.contains("Initialization Sequence Completed") {
                connected = true;
                print_status("✓", "VPN connected!", "green");
                println!(
                    "  {} Press {} to disconnect",
                    "│".dimmed(),
                    "Ctrl+C".bold()
                );
            } else if msg.contains("AUTH_FAILED") {
                print_status("✗", "Authentication failed — check your credentials", "red");
            } else if msg.contains("server_poll") || msg.contains("Server poll timeout") {
                print_status("⚠", "Server not responding, retrying...", "yellow");
            } else if msg.contains("dco-connect-timeout") || msg.contains("dco connect timeout") {
                print_status("⚠", "Connection timeout, retrying...", "yellow");
            } else if msg.contains("TLS Error") || msg.contains("TLS handshake failed") {
                print_status("✗", "TLS error — certificate issue", "red");
            } else if msg.contains("SIGTERM") || msg.contains("process exiting") {
                if connected {
                    print_status("⏏", "Disconnected", "cyan");
                }
            } else if msg.contains("TCP_CLIENT link remote") || msg.contains("UDP link remote") {
                if let Some(addr) = extract_address(msg) {
                    print_status("⟩", &format!("Connecting to {}", addr), "cyan");
                }
            } else if msg.contains("PUSH:") {
                if let Some(ip) = extract_ip_from_push(msg) {
                    print_status("⟩", &format!("Assigned IP: {}", ip), "green");
                }
            } else if msg.contains("ERROR") || msg.contains("fatal error") || msg.contains("Exiting") {
                print_status("✗", msg.trim(), "red");
            } else if msg.contains("SENT CONTROL") || msg.contains("PUSH_REQUEST") {
                print_status("⟩", "Authenticating...", "yellow");
            } else if msg.contains("Initial packet from") {
                print_status("🔑", "TLS negotiation started...", "yellow");
            }
            // Everything else is suppressed
        }

        let _ = stdout_handle.join();
        let _ = stderr_handle.join();
        let status = child.wait()?;

        if shutdown.load(Ordering::SeqCst) {
            if connected {
                print_status("⏏", "Disconnected", "cyan");
            }
        } else if !connected {
            println!();
            print_status("!", "Connection unsuccessful. Run with -v for details.", "yellow");
        }

        if !shutdown.load(Ordering::SeqCst) && !status.success() {
            std::process::exit(status.code().unwrap_or(1));
        }
    }

    Ok(())
}

/// Forward all arguments directly to the OpenVPN executable.
pub fn forward(args: &[String]) -> Result<(), Box<dyn std::error::Error>> {
    let openvpn = find_openvpn()?;

    let mut cmd = Command::new(&openvpn);
    for arg in args {
        cmd.arg(arg);
    }

    cmd.stdin(Stdio::inherit())
        .stdout(Stdio::inherit())
        .stderr(Stdio::inherit());

    let mut child = cmd.spawn()?;
    let status = child.wait()?;

    if !status.success() {
        std::process::exit(status.code().unwrap_or(1));
    }

    Ok(())
}

/// Find the `openvpn` executable in PATH.
fn find_openvpn() -> Result<std::path::PathBuf, Box<dyn std::error::Error>> {
    which::which("openvpn").map_err(|_| {
        "Could not find 'openvpn' in PATH. Make sure OpenVPN is installed.".into()
    })
}

/// Generate a TOTP code from an otpauth:// URI or a raw base32 secret.
fn generate_totp(otp_value: &str) -> Result<String, Box<dyn std::error::Error>> {
    let totp = if otp_value.starts_with("otpauth://") {
        TOTP::from_url(otp_value)
            .map_err(|e| format!("Failed to parse OTP URI: {}", e))?
    } else {
        TOTP::new(
            totp_rs::Algorithm::SHA1,
            6,
            1,
            30,
            totp_rs::Secret::Encoded(otp_value.to_string())
                .to_bytes()
                .map_err(|e| format!("Invalid base32 OTP secret: {}", e))?,
            None,
            String::new(),
        )
        .map_err(|e| format!("Failed to create TOTP: {}", e))?
    };

    let time = SystemTime::now()
        .duration_since(SystemTime::UNIX_EPOCH)?
        .as_secs();

    Ok(totp.generate(time))
}

/// Print a colored status line.
fn print_status(icon: &str, message: &str, color: &str) {
    let colored_msg = match color {
        "green" => format!("  {} {}", icon.green().bold(), message.green()),
        "yellow" => format!("  {} {}", icon.yellow().bold(), message.yellow()),
        "red" => format!("  {} {}", icon.red().bold(), message.red()),
        "cyan" => format!("  {} {}", icon.cyan().bold(), message.cyan()),
        _ => format!("  {} {}", icon, message),
    };
    println!("{}", colored_msg);
}

/// Strip the OpenVPN timestamp prefix (e.g., "2026-02-18 21:17:29 ").
fn strip_timestamp(line: &str) -> &str {
    if line.len() > 20 && line.as_bytes().get(4) == Some(&b'-') && line.as_bytes().get(13) == Some(&b':') {
        &line[20..]
    } else {
        line
    }
}

/// Extract address from OpenVPN log line.
fn extract_address(msg: &str) -> Option<String> {
    if let Some(start) = msg.find("[AF_INET]") {
        let addr = &msg[start + 9..];
        let end = addr.find(|c: char| !c.is_ascii_digit() && c != '.' && c != ':').unwrap_or(addr.len());
        Some(addr[..end].to_string())
    } else {
        None
    }
}

/// Extract IP from PUSH reply.
fn extract_ip_from_push(msg: &str) -> Option<String> {
    if let Some(idx) = msg.find("ifconfig ") {
        let rest = &msg[idx + 9..];
        let end = rest.find(' ').unwrap_or(rest.len());
        let ip = &rest[..end];
        if ip.contains('.') {
            return Some(ip.to_string());
        }
    }
    None
}

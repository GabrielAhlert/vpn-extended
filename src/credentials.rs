use crate::config::{AppConfig, VpnConfig};
use colored::Colorize;
use std::io::{self, Write};
use zeroize::Zeroizing;
use xcap::Monitor;
use rqrr::PreparedImage;
use image::DynamicImage;

const KEYRING_SERVICE: &str = "openvpn-wrapper";

/// Build the keyring entry for a secret (`name` is the config name, or `<config>-otp`).
///
/// On Windows the target names the Credential Manager entry. Elsewhere the default
/// store is used: on Linux (Secret Service) a custom target would create a separate
/// collection per entry, and on macOS the target must be a keychain domain.
fn keyring_entry(name: &str) -> keyring::Result<keyring::Entry> {
    #[cfg(target_os = "windows")]
    {
        keyring::Entry::new_with_target(&format!("openvpn-wrapper:{}", name), KEYRING_SERVICE, name)
    }
    #[cfg(not(target_os = "windows"))]
    {
        keyring::Entry::new(KEYRING_SERVICE, name)
    }
}

/// Human-readable name of the OS credential store.
fn keyring_store_name() -> &'static str {
    if cfg!(target_os = "windows") {
        "Windows Credential Manager"
    } else if cfg!(target_os = "macos") {
        "macOS Keychain"
    } else {
        "system keyring (Secret Service)"
    }
}

/// Remove one pair of surrounding quotes, as added by "Copy as path" or drag-and-drop.
fn strip_quotes(path: &str) -> &str {
    for quote in ['"', '\''] {
        if let Some(inner) = path.strip_prefix(quote).and_then(|p| p.strip_suffix(quote)) {
            return inner;
        }
    }
    path
}

/// Expand a leading `~` to the home directory (the shell does not expand it inside prompts).
fn expand_home(path: &str) -> String {
    let rest = if path == "~" {
        Some("")
    } else {
        path.strip_prefix("~/").or_else(|| path.strip_prefix("~\\"))
    };
    let home = std::env::var("HOME").or_else(|_| std::env::var("USERPROFILE"));
    match (rest, home) {
        (Some(rest), Ok(home)) => std::path::Path::new(&home).join(rest).to_string_lossy().to_string(),
        _ => path.to_string(),
    }
}

/// Prompt user for credentials and save them.
pub fn save_credentials(config_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    if config_name.is_empty() || !config_name.chars().all(|c| c.is_alphanumeric() || c == '-' || c == '_') {
        return Err("Config name must only contain letters, numbers, '-' or '_'.".into());
    }

    println!(
        "{} {}",
        "⟩".bold().cyan(),
        format!("Setting up credentials for '{}'", config_name).bold()
    );
    println!();

    // Prompt for .ovpn file path
    print!("  {} ", "Config file (.ovpn):".bold());
    io::stdout().flush()?;
    let mut ovpn_file = String::new();
    io::stdin().read_line(&mut ovpn_file)?;
    let ovpn_file = expand_home(strip_quotes(ovpn_file.trim()));

    if ovpn_file.is_empty() {
        return Err("Config file path cannot be empty".into());
    }

    let ovpn_path = std::path::Path::new(&ovpn_file);
    if !ovpn_path.exists() || !ovpn_path.is_file() {
        return Err(format!("File '{}' does not exist or is not a regular file", ovpn_file).into());
    }
    // Store an absolute path so `connect` works from any directory.
    let ovpn_file = std::path::absolute(ovpn_path)?.to_string_lossy().to_string();

    // Prompt for username
    print!("  {} ", "Username:".bold());
    io::stdout().flush()?;
    let mut username = String::new();
    io::stdin().read_line(&mut username)?;
    let username = username.trim().to_string();

    if username.is_empty() {
        return Err("Username cannot be empty".into());
    }

    // Prompt for password (hidden input)
    let password = Zeroizing::new(rpassword::prompt_password(format!("  {} ", "Password:".bold()))?);
    if password.is_empty() {
        return Err("Password cannot be empty".into());
    }

    // Prompt for OTP secret (optional)
    print!("  {} ", "OTP secret (optional, or 'scan' to capture QR from screen):".bold());
    io::stdout().flush()?;
    let mut otp = String::new();
    io::stdin().read_line(&mut otp)?;
    let mut otp_val = otp.trim().to_string();

    if otp_val.eq_ignore_ascii_case("scan") {
        match scan_qr_from_screen() {
            Ok(scanned_uri) => {
                println!("  {} QR code scanned successfully!", "✓".green().bold());
                otp_val = scanned_uri;
            }
            Err(e) => {
                println!("  {} Failed to scan QR code: {}", "✗".red().bold(), e);
                return Err("Failed to capture OTP from screen".into());
            }
        }
    }

    let otp = Zeroizing::new(otp_val);

    println!();

    // Store password in system keyring
    let entry = keyring_entry(config_name)?;
    entry.set_password(&password)?;
    println!(
        "  {} {}",
        "✓".green().bold(),
        format!("Password stored in {}", keyring_store_name()).green()
    );

    // Store OTP in keyring if provided
    if !otp.is_empty() {
        let otp_entry = keyring_entry(&format!("{}-otp", config_name))?;
        otp_entry.set_password(&otp)?;
        println!("  {} {}", "✓".green().bold(), "OTP secret stored securely".green());
    }

    // Save config metadata to JSON (no secrets here)
    let mut config = AppConfig::load()?;
    config.configs.insert(
        config_name.to_string(),
        VpnConfig {
            username,
            ovpn_file,
        },
    );
    config.save()?;

    println!();
    println!(
        "  {} {}",
        "✓".green().bold(),
        format!("Configuration '{}' saved!", config_name).green().bold()
    );
    Ok(())
}

/// Retrieve credentials for a given config name.
pub fn get_credentials(config_name: &str) -> Result<(String, Zeroizing<String>, Option<Zeroizing<String>>), Box<dyn std::error::Error>> {
    let config = AppConfig::load()?;
    let vpn_config = config
        .configs
        .get(config_name)
        .ok_or_else(|| format!("No saved config found for '{}'. Run 'save-auth {}' first.", config_name, config_name))?;

    let entry = keyring_entry(config_name)?;
    let password = entry.get_password().map_err(|e| {
        format!("Could not retrieve password: {}. Try 'save-auth {}' again.", e, config_name)
    })?;
    let password = Zeroizing::new(password);

    let otp = keyring_entry(&format!("{}-otp", config_name))
        .ok()
        .and_then(|e| e.get_password().ok())
        .map(Zeroizing::new);

    Ok((vpn_config.username.clone(), password, otp))
}

/// Capture all monitors and search for an OTPAuth QR Code.
fn scan_qr_from_screen() -> Result<String, Box<dyn std::error::Error>> {
    println!("  {} Scanning screens for QR codes...", "⟩".cyan());
    let monitors = Monitor::all().map_err(|e| format!("Failed to get monitors: {}", e))?;

    for monitor in monitors {
        let image = monitor.capture_image().map_err(|e| format!("Failed to capture image: {}", e))?;
        
        let luma_img = DynamicImage::ImageRgba8(image).into_luma8();
        let mut prepared = PreparedImage::prepare(luma_img);
        let grids = prepared.detect_grids();
        
        for grid in grids {
            if let Ok((_, content)) = grid.decode() {
                if content.starts_with("otpauth://") {
                    return Ok(content);
                }
            }
        }
    }
    
    Err("No valid otpauth:// QR code found on any screen. Please make sure the QR code is visible.".into())
}

/// List all saved configurations.
pub fn list_configs() -> Result<(), Box<dyn std::error::Error>> {
    let config = AppConfig::load()?;

    if config.configs.is_empty() {
        println!("  {} {}", "·".dimmed(), "No saved configurations.".dimmed());
        return Ok(());
    }

    println!("{}", "  Saved VPN configurations:".bold());
    println!();
    println!(
        "  {:<20} {:<20} {}",
        "NAME".bold().yellow(),
        "USERNAME".bold().yellow(),
        "OVPN FILE".bold().yellow()
    );
    println!("  {}", "─".repeat(60).dimmed());
    for (name, vpn_config) in &config.configs {
        println!(
            "  {:<20} {:<20} {}",
            name.green(),
            vpn_config.username,
            vpn_config.ovpn_file.dimmed()
        );
    }
    println!();

    Ok(())
}

/// Delete saved credentials for a config.
pub fn delete_credentials(config_name: &str) -> Result<(), Box<dyn std::error::Error>> {
    // Remove from keyring
    if let Ok(entry) = keyring_entry(config_name) {
        let _ = entry.delete_credential();
    }
    if let Ok(entry) = keyring_entry(&format!("{}-otp", config_name)) {
        let _ = entry.delete_credential();
    }

    // Remove from config
    let mut config = AppConfig::load()?;
    if config.configs.remove(config_name).is_some() {
        config.save()?;
        println!(
            "  {} {}",
            "✓".green().bold(),
            format!("Credentials deleted for '{}'", config_name).green()
        );
    } else {
        println!(
            "  {} {}",
            "·".dimmed(),
            format!("No config found for '{}'", config_name).dimmed()
        );
    }

    Ok(())
}

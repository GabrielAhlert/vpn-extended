use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::PathBuf;

const CONFIG_FILE: &str = "openvpn-wrapper.json";
const APP_NAME: &str = "openvpn-wrapper";

/// Represents a saved VPN configuration entry.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct VpnConfig {
    /// Username for this VPN config
    pub username: String,
    /// Path to the .ovpn config file
    pub ovpn_file: String,
}

/// Top-level configuration holding all saved VPN configs.
#[derive(Serialize, Deserialize, Debug, Default)]
pub struct AppConfig {
    pub configs: HashMap<String, VpnConfig>,
}

impl AppConfig {
    /// Load config from disk, or return default if file doesn't exist.
    pub fn load() -> io::Result<Self> {
        let path = Self::config_path()?;
        if !path.exists() {
            return Ok(Self::default());
        }
        let mut file = fs::File::open(&path)?;
        use fs2::FileExt;
        file.lock_shared()?;
        let mut content = String::new();
        use std::io::Read;
        file.read_to_string(&mut content)?;
        let config: AppConfig = serde_json::from_str(&content)
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;
        Ok(config)
    }

    /// Save config to disk.
    pub fn save(&self) -> io::Result<()> {
        let path = Self::config_path()?;
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let content = serde_json::to_string_pretty(self)
            .map_err(|e| io::Error::new(io::ErrorKind::Other, e))?;
        
        let mut options = fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        
        let mut file = options.open(&path)?;
        use fs2::FileExt;
        file.lock_exclusive()?;
        use std::io::Write;
        file.write_all(content.as_bytes())?;
        
        Ok(())
    }

    /// Get the path to the config file.
    fn config_path() -> io::Result<PathBuf> {
        let config_dir = dirs_config_dir()
            .ok_or_else(|| io::Error::new(io::ErrorKind::NotFound, "Could not find config directory"))?;
        Ok(config_dir.join(APP_NAME).join(CONFIG_FILE))
    }
}

/// Cross-platform config directory (without adding another dependency).
fn dirs_config_dir() -> Option<PathBuf> {
    #[cfg(target_os = "windows")]
    {
        std::env::var("APPDATA").ok().map(PathBuf::from)
    }
    #[cfg(target_os = "linux")]
    {
        std::env::var("XDG_CONFIG_HOME")
            .ok()
            .map(PathBuf::from)
            .or_else(|| {
                std::env::var("HOME")
                    .ok()
                    .map(|h| PathBuf::from(h).join(".config"))
            })
    }
    #[cfg(target_os = "macos")]
    {
        std::env::var("HOME")
            .ok()
            .map(|h| PathBuf::from(h).join("Library").join("Application Support"))
    }
}

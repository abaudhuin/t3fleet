use std::{
    fs::{self, DirBuilder},
    io::{self, Write},
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    process::Stdio,
};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use tempfile::NamedTempFile;
use tokio::process::Command;

#[derive(Deserialize, Serialize)]
pub struct Config {
    pub server: String,
    pub username: String,
    pub api_token: String,
    pub ssh_alias: String,
    pub sandbox_id: String,
    pub server_t3_port: u16,
    pub ssh_config: PathBuf,
    pub identity_file: PathBuf,
    pub known_hosts: PathBuf,
}

impl Config {
    pub fn read(path: &Path) -> Result<Self> {
        let file =
            fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        toml::from_str(&file).context("invalid t3fleet configuration")
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        atomic_write(path, toml::to_string_pretty(self)?.as_bytes())
    }

    pub fn public_key(&self) -> Result<String> {
        public_key(&self.identity_file)
    }
}

pub fn default_dir() -> Result<PathBuf> {
    Ok(dirs::config_dir()
        .context("could not find configuration directory")?
        .join("t3fleet"))
}

pub fn default_ssh_config() -> Result<PathBuf> {
    Ok(dirs::home_dir()
        .context("could not find home directory")?
        .join(".ssh/config"))
}

pub fn absolute(path: PathBuf) -> Result<PathBuf> {
    Ok(std::path::absolute(path)?)
}

pub fn create_dir(path: &Path) -> Result<()> {
    DirBuilder::new()
        .recursive(true)
        .mode(0o700)
        .create(path)
        .with_context(|| format!("creating {}", path.display()))
}

pub fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().context("file path has no parent")?;
    let mut temp = NamedTempFile::new_in(parent)?;
    temp.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temp.write_all(contents)?;
    temp.persist(path)
        .with_context(|| format!("writing {}", path.display()))?;
    Ok(())
}

fn public_key(identity: &Path) -> Result<String> {
    let file = identity.with_extension("pub");
    Ok(fs::read_to_string(&file)
        .with_context(|| format!("reading {}", file.display()))?
        .trim_end_matches(['\r', '\n'])
        .to_owned())
}

pub async fn ensure_key(path: &Path) -> Result<String> {
    let public = path.with_extension("pub");
    if !path.try_exists()? {
        let temp = tempfile::tempdir_in(path.parent().context("identity path has no parent")?)?;
        let generated = temp.path().join("id_ed25519");
        let status = Command::new("ssh-keygen")
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "t3fleet", "-f"])
            .arg(&generated)
            .stdin(Stdio::null())
            .status()
            .await
            .context("running ssh-keygen")?;
        ensure!(status.success(), "ssh-keygen failed");
        match fs::hard_link(&generated, path) {
            Ok(()) => atomic_write(&public, &fs::read(generated.with_extension("pub"))?)?,
            Err(error) if error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.into()),
        }
    }
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    if !public.try_exists()? {
        let output = Command::new("ssh-keygen")
            .args(["-y", "-f"])
            .arg(path)
            .stdin(Stdio::null())
            .output()
            .await
            .context("reading SSH identity with ssh-keygen")?;
        ensure!(output.status.success(), "could not extract SSH public key");
        atomic_write(&public, &output.stdout)?;
    }
    public_key(path)
}

fn path_text(path: &Path) -> Result<&str> {
    let path = path.to_str().context("OpenSSH paths must be UTF-8")?;
    ensure!(
        !path.chars().any(char::is_control),
        "control character in OpenSSH path"
    );
    Ok(path)
}

fn ssh_quote(text: &str) -> String {
    format!(
        "\"{}\"",
        text.replace('%', "%%")
            .replace('\\', "\\\\")
            .replace('"', "\\\"")
    )
}

fn proxy_path(path: &Path) -> Result<String> {
    let text = path_text(path)?.replace('%', "%%").replace('\'', "'\"'\"'");
    Ok(format!("'{text}'"))
}

pub fn validate_alias(alias: &str) -> Result<()> {
    ensure!(
        alias.starts_with("t3fleet-")
            && alias.len() > "t3fleet-".len()
            && alias
                .bytes()
                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_'),
        "invalid fleet SSH alias"
    );
    Ok(())
}

pub fn write_ssh(config: &Config, config_path: &Path, dir: &Path) -> Result<()> {
    let alias = &config.ssh_alias;
    validate_alias(alias)?;
    let binary = proxy_path(&std::env::current_exe()?)?;
    let config_arg = proxy_path(config_path)?;
    let identity = ssh_quote(path_text(&config.identity_file)?);
    let known = ssh_quote(path_text(&config.known_hosts)?);
    let fragment_dir = dir.join("ssh");
    let fragment_path = fragment_dir.join(format!("{alias}.conf"));
    let ssh_config = &config.ssh_config;
    create_dir(&fragment_dir)?;
    let fragment = format!(
        "Host {alias}\n  User user\n  IdentityFile {identity}\n  IdentitiesOnly yes\n  \
         HostKeyAlias {alias}\n  UserKnownHostsFile {known}\n  StrictHostKeyChecking yes\n  \
         ServerAliveInterval 30\n  ServerAliveCountMax 3\n  \
         ProxyCommand {binary} ssh-proxy --config {config_arg} --alias {alias}\n"
    );
    atomic_write(&fragment_path, fragment.as_bytes())?;

    create_dir(
        ssh_config
            .parent()
            .context("SSH configuration has no parent")?,
    )?;
    let mut pattern = String::new();
    for ch in path_text(&fragment_dir)?.chars() {
        if matches!(ch, '*' | '?' | '[' | ']' | '\\') {
            pattern.push('\\');
        }
        pattern.push(ch);
    }
    let include = format!("Include {}", ssh_quote(&format!("{pattern}/*.conf")));
    let current = read_or_empty(ssh_config)?;
    let mut updated = format!("{include}\n");
    for line in current.split_inclusive('\n') {
        if line.trim() != include {
            updated.push_str(line);
        }
    }
    if updated != current {
        atomic_write(ssh_config, updated.as_bytes())?;
    }
    Ok(())
}

fn read_or_empty(path: &Path) -> Result<String> {
    match fs::read_to_string(path) {
        Ok(content) => Ok(content),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(String::new()),
        Err(error) => Err(error).with_context(|| format!("reading {}", path.display())),
    }
}

pub fn pin_host(path: &Path, alias: &str, host_key: &str) -> Result<()> {
    validate_alias(alias)?;
    let mut parts = host_key.split_ascii_whitespace();
    let algorithm = parts.next().context("missing SSH host key algorithm")?;
    let blob = parts.next().context("missing SSH host key data")?;
    ensure!(
        !host_key.contains(['\r', '\n', '\0'])
            && (algorithm.starts_with("ssh-") || algorithm.starts_with("ecdsa-"))
            && algorithm
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"-@.".contains(&b))
            && blob
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"/+=".contains(&b)),
        "invalid SSH host key from fleet server"
    );
    let mut updated = format!("{alias} {algorithm} {blob}\n");
    let current = read_or_empty(path)?;
    for line in current.split_inclusive('\n') {
        if line.split_ascii_whitespace().next() != Some(alias) {
            updated.push_str(line);
        }
    }
    atomic_write(path, updated.as_bytes())
}

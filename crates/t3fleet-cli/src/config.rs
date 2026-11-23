use std::{
    fs::{self, DirBuilder},
    io::{self, Write},
    path::{Path, PathBuf},
    process::Stdio,
};

#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use t3fleet_protocol::{DEFAULT_SANDBOX_NAME, valid_sandbox_name};
use tempfile::{NamedTempFile, TempPath};
use tokio::process::Command;

pub const SSH_PROGRAM: &str = if cfg!(windows) { "ssh.exe" } else { "ssh" };
const SSH_KEYGEN: &str = if cfg!(windows) {
    "ssh-keygen.exe"
} else {
    "ssh-keygen"
};

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

    pub fn alias(&self, sandbox: Option<&str>) -> Result<String> {
        let name = sandbox.unwrap_or(DEFAULT_SANDBOX_NAME);
        ensure!(valid_sandbox_name(name), "invalid sandbox name");
        validate_alias(&self.ssh_alias)?;
        Ok(if name == DEFAULT_SANDBOX_NAME {
            self.ssh_alias.clone()
        } else {
            format!("{}-{name}", self.ssh_alias)
        })
    }

    pub fn sandbox_name<'a>(&self, alias: &'a str) -> Result<Option<&'a str>> {
        validate_alias(alias)?;
        validate_alias(&self.ssh_alias)?;
        if alias == self.ssh_alias {
            return Ok(None);
        }
        let name = alias
            .strip_prefix(&self.ssh_alias)
            .and_then(|suffix| suffix.strip_prefix('-'))
            .filter(|name| *name != DEFAULT_SANDBOX_NAME && valid_sandbox_name(name))
            .context("SSH alias does not match fleet configuration")?;
        Ok(Some(name))
    }

    fn fragment_dir(&self) -> Result<PathBuf> {
        Ok(self
            .identity_file
            .parent()
            .context("identity path has no parent")?
            .join("ssh"))
    }

    pub fn known_hosts_for(&self, alias: &str) -> Result<PathBuf> {
        if self.sandbox_name(alias)?.is_none() {
            return Ok(self.known_hosts.clone());
        }
        Ok(self.fragment_dir()?.join(format!("{alias}.known_hosts")))
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
    let mut builder = DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    builder.mode(0o700);
    builder
        .create(path)
        .with_context(|| format!("creating {}", path.display()))
}

pub fn atomic_write(path: &Path, contents: &[u8]) -> Result<()> {
    let parent = path.parent().context("file path has no parent")?;
    let mut temp = NamedTempFile::new_in(parent)?;
    #[cfg(unix)]
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
        let status = Command::new(SSH_KEYGEN)
            .args(["-q", "-t", "ed25519", "-N", "", "-C", "t3fleet", "-f"])
            .arg(&generated)
            .stdin(Stdio::null())
            .status()
            .await
            .context("running ssh-keygen")?;
        ensure!(status.success(), "ssh-keygen failed");
        let generated_public = generated.with_extension("pub");
        // Move the key without overwriting a key from a concurrent join or changing its ACL.
        match TempPath::try_from_path(generated)?.persist_noclobber(path) {
            Ok(()) => atomic_write(&public, &fs::read(generated_public)?)?,
            Err(error) if error.error.kind() == io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(error.error.into()),
        }
    }
    #[cfg(unix)]
    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    if !public.try_exists()? {
        let output = Command::new(SSH_KEYGEN)
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
    let text = path_text(path)?.replace('%', "%%");
    #[cfg(windows)]
    let quoted = format!("\"{}\"", text.replace('"', "\\\""));
    #[cfg(not(windows))]
    let quoted = format!("'{}'", text.replace('\'', "'\"'\"'"));
    Ok(quoted)
}

fn ssh_path(path: &Path) -> Result<String> {
    let text = path_text(path)?;
    #[cfg(windows)]
    let normalized = text.replace('\\', "/");
    #[cfg(windows)]
    let text = normalized.as_str();
    Ok(ssh_quote(text))
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

pub fn write_ssh(config: &Config, config_path: &Path, alias: &str) -> Result<()> {
    let binary = proxy_path(&std::env::current_exe()?)?;
    let config_arg = proxy_path(config_path)?;
    let identity = ssh_path(&config.identity_file)?;
    let known = ssh_path(&config.known_hosts_for(alias)?)?;
    let fragment_dir = config.fragment_dir()?;
    let fragment_path = fragment_dir.join(format!("{alias}.conf"));
    create_dir(&fragment_dir)?;
    let fragment = format!(
        "Host {alias}\n  User user\n  IdentityFile {identity}\n  IdentitiesOnly yes\n  \
         HostKeyAlias {alias}\n  UserKnownHostsFile {known}\n  StrictHostKeyChecking yes\n  \
         ServerAliveInterval 30\n  ServerAliveCountMax 3\n  \
         ProxyCommand {binary} ssh-proxy --config {config_arg} --alias {alias}\n"
    );
    atomic_write(&fragment_path, fragment.as_bytes())
}

pub fn include_ssh(config: &Config) -> Result<()> {
    let ssh_config = &config.ssh_config;
    let fragment_dir = config.fragment_dir()?;
    create_dir(&fragment_dir)?;
    create_dir(
        ssh_config
            .parent()
            .context("SSH configuration has no parent")?,
    )?;
    let mut pattern = String::new();
    let dir = path_text(&fragment_dir)?;
    #[cfg(windows)]
    let dir = dir.replace('\\', "/");
    for ch in dir.chars() {
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

pub fn remove_ssh(config: &Config, alias: &str) -> Result<()> {
    ensure!(
        config.sandbox_name(alias)?.is_some(),
        "cannot remove the default SSH alias"
    );
    for path in [
        config.fragment_dir()?.join(format!("{alias}.conf")),
        config.known_hosts_for(alias)?,
    ] {
        match fs::remove_file(&path) {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => {
                return Err(error).with_context(|| format!("removing {}", path.display()));
            }
        }
    }
    Ok(())
}

pub fn prune_ssh(config: &Config, aliases: &[String]) -> Result<()> {
    for entry in fs::read_dir(config.fragment_dir()?)? {
        let entry = entry?;
        let filename = entry.file_name();
        let Some(alias) = filename
            .to_str()
            .and_then(|name| name.strip_suffix(".conf"))
        else {
            continue;
        };
        if !aliases.iter().any(|current| current == alias)
            && matches!(config.sandbox_name(alias), Ok(Some(_)))
        {
            remove_ssh(config, alias)?;
        }
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

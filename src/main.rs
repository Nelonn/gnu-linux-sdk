use ar::Archive as ArArchive;
use clap::{Parser, Subcommand};
use flate2::read::GzDecoder;
use flate2::write::GzEncoder;
use flate2::Compression;
use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use std::fs::{self, File};
use std::io::{self, Read, Seek, Write};
use std::path::{Path, PathBuf};
use tar::Builder;
use thiserror::Error;
use xz2::read::XzDecoder;

mod cache;
mod debian;
mod toolchain;

use cache::FileCache;
use debian::DebianFetcher;
use toolchain::get_toolchain_content;

#[cfg(windows)]
fn has_symlink_privileges() -> bool {
    use std::os::windows::fs::symlink_file;
    let temp_dir = std::env::temp_dir();
    let test_link = temp_dir.join(format!("symlink_test_{}", std::process::id()));
    let test_target = temp_dir.join(format!("target_test_{}", std::process::id()));

    if std::fs::write(&test_target, "").is_err() {
        return false;
    }

    let result = symlink_file(&test_target, &test_link);

    let _ = std::fs::remove_file(&test_link);
    let _ = std::fs::remove_file(&test_target);

    result.is_ok()
}

#[cfg(windows)]
fn create_symlink(link_target: &Path, link_path: &Path, has_privileges: bool) -> Result<()> {
    use std::os::windows::fs::{symlink_dir, symlink_file};

    if !has_privileges {
        return Ok(());
    }

    let full_target = if link_target.is_absolute() {
        link_target.to_path_buf()
    } else {
        link_path.parent()
            .map(|p| p.join(link_target))
            .unwrap_or_else(|| link_target.to_path_buf())
    };

    let result = if full_target.is_dir() {
        symlink_dir(link_target, link_path)
    } else {
        symlink_file(link_target, link_path)
    };

    if let Err(e) = result {
        eprintln!(
            "Warning: Failed to create symlink {} -> {}: {}",
            link_path.display(),
            link_target.display(),
            e
        );
    }

    Ok(())
}

#[cfg(windows)]
fn create_dir_symlink(link_target: &Path, link_path: &Path, has_privileges: bool) -> Result<()> {
    use std::os::windows::fs::symlink_dir;

    if !has_privileges {
        return Ok(());
    }

    if let Err(e) = symlink_dir(link_target, link_path) {
        eprintln!(
            "Warning: Failed to create directory symlink {} -> {}: {}",
            link_path.display(),
            link_target.display(),
            e
        );
    }

    Ok(())
}

#[cfg(unix)]
fn create_symlink(link_target: &Path, link_path: &Path, _has_privileges: bool) -> Result<()> {
    std::os::unix::fs::symlink(link_target, link_path)?;
    Ok(())
}

#[cfg(unix)]
fn create_dir_symlink(link_target: &Path, link_path: &Path, _has_privileges: bool) -> Result<()> {
    std::os::unix::fs::symlink(link_target, link_path)?;
    Ok(())
}

#[derive(Error, Debug)]
pub enum SysrootError {
    #[error("Failed to parse config: {0}")]
    ConfigParse(#[from] toml::de::Error),

    #[error("IO error: {0}")]
    Io(#[from] io::Error),

    #[error("HTTP error: {0}")]
    Http(#[from] reqwest::Error),

    #[error("Package not found: {0}")]
    PackageNotFound(String),

    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
}

pub type Result<T> = std::result::Result<T, SysrootError>;

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Strategy {
    pub method: String,
    pub suite: String,
    pub mirrors: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct PackageGroup {
    pub packages: Vec<String>,
    #[serde(default)]
    pub requires: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Profile {
    pub groups: Vec<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct Config {
    pub strategy: Strategy,
    #[serde(default)]
    pub groups: HashMap<String, PackageGroup>,
    #[serde(default)]
    pub profiles: HashMap<String, Profile>,
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = fs::read_to_string(path)?;
        let config: Config = toml::from_str(&content)?;
        Ok(config)
    }

    pub fn resolve_packages(&self, profile_name: &str) -> Result<Vec<String>> {
        let profile = self
            .profiles
            .get(profile_name)
            .ok_or_else(|| SysrootError::InvalidConfig(format!("Profile '{}' not found", profile_name)))?;

        let mut resolved = Vec::new();
        let mut visited = HashSet::new();
        let mut in_stack = HashSet::new();

        for group_name in &profile.groups {
            self.resolve_group(group_name, &mut resolved, &mut visited, &mut in_stack)?;
        }

        Ok(resolved)
    }

    fn resolve_group(
        &self,
        group_name: &str,
        resolved: &mut Vec<String>,
        visited: &mut HashSet<String>,
        in_stack: &mut HashSet<String>,
    ) -> Result<()> {
        if visited.contains(group_name) {
            return Ok(());
        }

        if in_stack.contains(group_name) {
            return Err(SysrootError::InvalidConfig(format!(
                "Circular dependency detected involving group '{}'",
                group_name
            )));
        }

        in_stack.insert(group_name.to_string());

        let group = self
            .groups
            .get(group_name)
            .ok_or_else(|| SysrootError::InvalidConfig(format!("Group '{}' not found", group_name)))?;

        for dep in &group.requires {
            self.resolve_group(dep, resolved, visited, in_stack)?;
        }

        for pkg in &group.packages {
            if !resolved.contains(pkg) {
                resolved.push(pkg.clone());
            }
        }

        visited.insert(group_name.to_string());
        in_stack.remove(group_name);

        Ok(())
    }
}

#[derive(Debug, Clone)]
pub struct PackageInfo {
    pub name: String,
    pub version: String,
    pub architecture: String,
    pub filename: String,
    pub download_url: String,
}

pub trait PackageConsumer {
    fn on_start(&mut self, pkg: &PackageInfo) -> Result<()> {
        let _ = pkg;
        Ok(())
    }

    fn consume(&mut self, pkg: &PackageInfo, deb_data: &[u8]) -> Result<()>;

    fn on_complete(&mut self, pkg: &PackageInfo) -> Result<()> {
        let _ = pkg;
        Ok(())
    }
}

pub struct TarConsumer<W: Write> {
    builder: Builder<GzEncoder<W>>,
    sysroot_prefix: String,
}

impl<W: Write> TarConsumer<W> {
    pub fn new(writer: W, sysroot_prefix: &str) -> Result<Self> {
        let encoder = GzEncoder::new(writer, Compression::default());
        let builder = Builder::new(encoder);
        Ok(Self {
            builder,
            sysroot_prefix: sysroot_prefix.to_string(),
        })
    }

    fn extract_data_tar(&self, deb_data: &[u8]) -> Result<Vec<u8>> {
        let mut ar = ArArchive::new(deb_data);

        while let Some(entry_result) = ar.next_entry() {
            let mut entry = entry_result?;
            let name = entry.header().identifier();
            let name_str = String::from_utf8_lossy(name).to_string();

            if name_str.starts_with("data.tar") {
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;

                if name_str.ends_with(".gz") {
                    let mut decoder = GzDecoder::new(&data[..]);
                    let mut extracted = Vec::new();
                    decoder.read_to_end(&mut extracted)?;
                    return Ok(extracted);
                } else if name_str.ends_with(".xz") {
                    let mut decoder = XzDecoder::new(&data[..]);
                    let mut extracted = Vec::new();
                    decoder.read_to_end(&mut extracted)?;
                    return Ok(extracted);
                } else {
                    return Ok(data);
                }
            }
        }

        Err(SysrootError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "No data.tar found in .deb package",
        )))
    }

    fn add_to_tar(&mut self, data_tar: &[u8]) -> Result<()> {
        let mut inner_tar = tar::Archive::new(data_tar);

        for entry_result in inner_tar.entries()? {
            let mut entry = entry_result?;
            let path = entry.path()?.to_path_buf();

            let target_path = match path.strip_prefix("/") {
                Ok(rel) => format!("{}/{}", self.sysroot_prefix, rel.display()),
                Err(_) => format!("{}/{}", self.sysroot_prefix, path.display()),
            };

            let entry_type = entry.header().entry_type();

            if entry_type.is_dir() {
                let mut header = tar::Header::new_gnu();
                header.set_size(0);
                header.set_mode(0o755);
                header.set_mtime(0);
                header.set_entry_type(tar::EntryType::Directory);
                header.set_cksum();
                self.builder.append_data(&mut header, &target_path, &[][..])?;
            } else if entry_type.is_file() {
                let size = entry.header().size()?;
                let mut contents = Vec::with_capacity(size as usize);
                entry.read_to_end(&mut contents)?;

                let mut header = tar::Header::new_gnu();
                header.set_size(contents.len() as u64);
                header.set_mode(0o644);
                header.set_mtime(0);
                header.set_cksum();

                self.builder
                    .append_data(&mut header, &target_path, &contents[..])?;
            } else if entry_type.is_symlink() {
                if let Some(link_name) = entry.link_name()? {
                    let link_target = link_name.to_path_buf();
                    let size = link_target.to_string_lossy().len() as u64;
                    
                    let mut header = tar::Header::new_gnu();
                    header.set_size(size);
                    header.set_mode(0o777);
                    header.set_mtime(0);
                    header.set_entry_type(tar::EntryType::Symlink);
                    header.set_cksum();
                    
                    self.builder.append_link(&mut header, &target_path, &link_target)?;
                }
            }
        }

        Ok(())
    }
}

impl<W: Write + Seek> PackageConsumer for TarConsumer<W> {
    fn consume(&mut self, pkg: &PackageInfo, deb_data: &[u8]) -> Result<()> {
        eprintln!("    TarConsumer: consuming {} ({} bytes)", pkg.name, deb_data.len());
        eprintln!("    TarConsumer: extracting data.tar...");
        let data_tar = self.extract_data_tar(deb_data)?;
        eprintln!("    TarConsumer: extracted {} bytes from data.tar", data_tar.len());
        eprintln!("    TarConsumer: adding to archive...");
        self.add_to_tar(&data_tar)?;
        eprintln!("    TarConsumer: done");
        Ok(())
    }

    fn on_complete(&mut self, _pkg: &PackageInfo) -> Result<()> {
        Ok(())
    }
}

impl<W: Write> TarConsumer<W> {
    pub fn finish(mut self) -> Result<()> {
        self.builder.finish()?;
        Ok(())
    }
}

pub struct DirConsumer {
    output_dir: PathBuf,
    #[cfg(windows)]
    has_symlink_privileges: bool,
    lib_symlink_created: bool,
}

impl DirConsumer {
    pub fn new(output_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&output_dir)?;
        #[cfg(windows)]
        let has_symlink_privileges = has_symlink_privileges();
        Ok(Self {
            output_dir,
            #[cfg(windows)]
            has_symlink_privileges,
            lib_symlink_created: false,
        })
    }

    fn extract_data_tar(&self, deb_data: &[u8]) -> Result<Vec<u8>> {
        let mut ar = ArArchive::new(deb_data);

        while let Some(entry_result) = ar.next_entry() {
            let mut entry = entry_result?;
            let name = entry.header().identifier();
            let name_str = String::from_utf8_lossy(name).to_string();

            if name_str.starts_with("data.tar") {
                let mut data = Vec::new();
                entry.read_to_end(&mut data)?;

                if name_str.ends_with(".gz") {
                    let mut decoder = GzDecoder::new(&data[..]);
                    let mut extracted = Vec::new();
                    decoder.read_to_end(&mut extracted)?;
                    return Ok(extracted);
                } else if name_str.ends_with(".xz") {
                    let mut decoder = XzDecoder::new(&data[..]);
                    let mut extracted = Vec::new();
                    decoder.read_to_end(&mut extracted)?;
                    return Ok(extracted);
                } else {
                    return Ok(data);
                }
            }
        }

        Err(SysrootError::Io(io::Error::new(
            io::ErrorKind::InvalidData,
            "No data.tar found in .deb package",
        )))
    }

    fn extract_to_dir(&mut self, data_tar: &[u8]) -> Result<()> {
        let mut inner_tar = tar::Archive::new(data_tar);

        for entry_result in inner_tar.entries()? {
            let mut entry = entry_result?;
            let path = entry.path()?.to_path_buf();

            let dest_path = match path.strip_prefix("/") {
                Ok(rel) => self.output_dir.join(rel),
                Err(_) => self.output_dir.join(&path),
            };

            let entry_type = entry.header().entry_type();

            if entry_type.is_dir() {
                fs::create_dir_all(&dest_path)?;
            } else if entry_type.is_file() {
                if let Some(parent) = dest_path.parent() {
                    fs::create_dir_all(parent)?;
                }
                entry.unpack(&dest_path)?;
            } else if entry_type.is_symlink() {
                if let Some(link_name) = entry.link_name()? {
                    if let Some(parent) = dest_path.parent() {
                        fs::create_dir_all(parent)?;
                    }
                    let _ = fs::remove_file(&dest_path);
                    #[cfg(windows)]
                    create_symlink(&link_name, &dest_path, self.has_symlink_privileges)?;
                    #[cfg(unix)]
                    create_symlink(&link_name, &dest_path, false)?;
                }
            }
        }

        if !self.lib_symlink_created {
            let lib_dir = self.output_dir.join("lib");
            let lib64_dir = self.output_dir.join("lib64");
            let usr_lib_dir = self.output_dir.join("usr").join("lib");
            let usr_lib64_dir = self.output_dir.join("usr").join("lib64");

            if !usr_lib_dir.exists() {
                let _ = fs::create_dir_all(&usr_lib_dir);
            }
            if !usr_lib64_dir.exists() {
                let _ = fs::create_dir_all(&usr_lib64_dir);
            }
            
            if !lib_dir.exists() && !lib_dir.is_symlink() {
                #[cfg(windows)]
                let _ = create_dir_symlink(Path::new("usr/lib"), &lib_dir, self.has_symlink_privileges);
                #[cfg(unix)]
                let _ = create_dir_symlink(Path::new("usr/lib"), &lib_dir, false);
            }
            
            if !lib64_dir.exists() && !lib64_dir.is_symlink() {
                #[cfg(windows)]
                let _ = create_dir_symlink(Path::new("usr/lib64"), &lib64_dir, self.has_symlink_privileges);
                #[cfg(unix)]
                let _ = create_dir_symlink(Path::new("usr/lib64"), &lib64_dir, false);
            }
            
            self.lib_symlink_created = true;
        }

        Ok(())
    }
}

impl PackageConsumer for DirConsumer {
    fn consume(&mut self, _pkg: &PackageInfo, deb_data: &[u8]) -> Result<()> {
        let data_tar = self.extract_data_tar(deb_data)?;
        self.extract_to_dir(&data_tar)?;
        Ok(())
    }
}

pub struct FetchConsumer {
    output_dir: PathBuf,
}

impl FetchConsumer {
    pub fn new(output_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&output_dir)?;
        Ok(Self { output_dir })
    }
}

impl PackageConsumer for FetchConsumer {
    fn consume(&mut self, pkg: &PackageInfo, deb_data: &[u8]) -> Result<()> {
        let filename = format!("{}_{}_{}.deb", pkg.name, pkg.version, pkg.architecture);
        let path = self.output_dir.join(&filename);
        let mut file = File::create(&path)?;
        file.write_all(deb_data)?;
        println!("  Saved: {}", path.display());
        Ok(())
    }
}

pub struct SysrootBuilder {
    config: Config,
    fetcher: DebianFetcher,
    cache: FileCache,
}

impl SysrootBuilder {
    pub fn new(
        config: Config,
        architecture: String,
        cache_dir: Option<PathBuf>,
        cache_enabled: bool,
    ) -> Result<Self> {
        let cache = FileCache::new(
            cache_dir.unwrap_or_else(|| PathBuf::from(".cache")),
            cache_enabled,
        )?;

        let fetcher = DebianFetcher::new(
            config.strategy.suite.clone(),
            architecture,
            config.strategy.mirrors.clone(),
        );

        Ok(Self {
            config,
            fetcher,
            cache,
        })
    }

    pub async fn build<C: PackageConsumer>(&self, profile_name: &str, consumer: &mut C) -> Result<()> {
        println!("Resolving packages for profile '{}'...", profile_name);
        let packages = self.config.resolve_packages(profile_name)?;
        println!("Found {} packages to process", packages.len());

        for pkg_name in &packages {
            println!("Processing {}...", pkg_name);

            let pkg_info = self.fetcher.fetch_package(pkg_name)?;

            consumer.on_start(&pkg_info)?;

            let deb_data = if self.cache.has_cached(&pkg_info.name, &pkg_info.version) {
                println!("  Using cached {} {}", pkg_info.name, pkg_info.version);
                self.cache.load(&pkg_info.name, &pkg_info.version)?
            } else {
                println!("  Downloading {} {}...", pkg_info.name, pkg_info.version);
                let data = self.fetcher.download_package(&pkg_info).await?;
                self.cache.save(&pkg_info.name, &pkg_info.version, &data)?;
                data
            };

            consumer.consume(&pkg_info, &deb_data)?;
            consumer.on_complete(&pkg_info)?;
        }

        Ok(())
    }

    pub async fn initialize(&mut self) -> Result<()> {
        self.fetcher.initialize().await
    }

    pub fn write_toolchain_file(&self, output_dir: &Path) -> Result<()> {
        let toolchain_content = get_toolchain_content();
        let toolchain_path = output_dir.join("toolchain.cmake");
        fs::write(&toolchain_path, toolchain_content)?;
        println!("Toolchain file written to: {}", toolchain_path.display());
        Ok(())
    }
}

#[derive(Parser, Debug)]
#[command(name = "gnu-linux-sdk")]
#[command(about = "Build sysroot from Debian packages")]
pub struct Cli {
    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    Build {
        #[arg(short, long)]
        config: PathBuf,

        #[arg(short, long)]
        profile: String,

        #[arg(short, long)]
        output: PathBuf,

        #[arg(short, long, default_value = "amd64")]
        arch: String,

        #[arg(long, default_value = "false")]
        no_cache: bool,

        #[arg(long, default_value = ".package-cache")]
        cache_dir: PathBuf,

        #[arg(long, default_value = "true")]
        toolchain: bool,
    },

    Extract {
        #[arg(short, long)]
        config: PathBuf,

        #[arg(short, long)]
        profile: String,

        #[arg(short, long)]
        output: PathBuf,

        #[arg(short, long, default_value = "amd64")]
        arch: String,

        #[arg(long, default_value = "false")]
        no_cache: bool,

        #[arg(long, default_value = ".package-cache")]
        cache_dir: PathBuf,

        #[arg(long, default_value = "true")]
        toolchain: bool,
    },

    Fetch {
        #[arg(short, long)]
        config: PathBuf,

        #[arg(short, long)]
        profile: String,

        #[arg(short, long)]
        output: PathBuf,

        #[arg(short, long, default_value = "amd64")]
        arch: String,

        #[arg(long, default_value = "false")]
        no_cache: bool,

        #[arg(long, default_value = ".package-cache")]
        cache_dir: PathBuf,

        #[arg(long, default_value = "false")]
        toolchain: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    #[cfg(windows)]
    if !has_symlink_privileges() {
        eprintln!(
            "Warning: Windows symlink privileges not available.\n\
            \tEnable Developer Mode or run as Administrator to create symlinks."
        );
    }

    match cli.command {
        Commands::Build {
            config,
            profile,
            output,
            arch,
            no_cache,
            cache_dir,
            toolchain,
        } => {
            let config = Config::load(&config)?;
            let mut builder = SysrootBuilder::new(config, arch, Some(cache_dir), !no_cache)?;

            builder.initialize().await?;

            let output_str = output.to_string_lossy();
            if output_str.ends_with(".tar.gz") || output_str.ends_with(".tgz") {
                let file = File::create(&output)?;
                let mut consumer = TarConsumer::new(file, "sysroot")?;

                builder.build(&profile, &mut consumer).await?;
                consumer.finish()?;

                println!("Sysroot built: {}", output.display());
            } else {
                let mut consumer = DirConsumer::new(output.clone())?;

                builder.build(&profile, &mut consumer).await?;

                if toolchain {
                    builder.write_toolchain_file(&output)?;
                }

                println!("Sysroot extracted to: {}", output.display());
            }
        }

        Commands::Extract {
            config,
            profile,
            output,
            arch,
            no_cache,
            cache_dir,
            toolchain,
        } => {
            let config = Config::load(&config)?;
            let mut builder = SysrootBuilder::new(config, arch, Some(cache_dir), !no_cache)?;

            builder.initialize().await?;

            let mut consumer = DirConsumer::new(output.clone())?;

            builder.build(&profile, &mut consumer).await?;

            if toolchain {
                builder.write_toolchain_file(&output)?;
            }

            println!("Sysroot extracted to: {}", output.display());
        }

        Commands::Fetch {
            config,
            profile,
            output,
            arch,
            no_cache,
            cache_dir,
            toolchain,
        } => {
            let config = Config::load(&config)?;
            let mut builder = SysrootBuilder::new(config, arch, Some(cache_dir), !no_cache)?;

            builder.initialize().await?;

            let mut consumer = FetchConsumer::new(output.clone())?;

            builder.build(&profile, &mut consumer).await?;

            if toolchain {
                builder.write_toolchain_file(&output)?;
            }

            println!("Packages fetched to: {}", output.display());
        }
    }

    Ok(())
}

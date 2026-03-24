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
use anyhow::{Context, bail};
use futures::stream::{self, StreamExt};
use tar::Builder;
use xz2::read::XzDecoder;
use zip::write::ZipWriter;
use zip::write::SimpleFileOptions;

mod cache;
mod debian;
mod toolchain;

use cache::FileCache;
use debian::DebianFetcher;
use toolchain::get_toolchain_content;

/// Normalise a symlink target coming out of a Unix tar archive so that
/// Windows `CreateSymbolicLink` can resolve it:
///
///   ./usr/lib/x86_64-linux-gnu  →  usr\lib\x86_64-linux-gnu
///   /usr/lib                    →  usr\lib
///   ../lib/libc.so.6            →  ..\lib\libc.so.6
#[cfg(windows)]
fn normalize_symlink_target(link_target: &Path) -> PathBuf {
    let target_str = link_target.to_string_lossy();

    // Strip a leading "./" — Windows sees it as a syntax error
    let s = target_str.strip_prefix("./").unwrap_or(&target_str);

    // Strip a leading "/" — absolute Unix paths become relative ones
    let s = s.strip_prefix('/').unwrap_or(s);

    // Replace every forward slash with a backslash
    PathBuf::from(s.replace('/', "\\"))
}

#[cfg(unix)]
fn normalize_symlink_target(link_target: &Path) -> PathBuf {
    link_target.to_path_buf()
}

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
    use std::os::windows::fs::symlink_file;

    if !has_privileges {
        return Ok(());
    }

    let normalized = normalize_symlink_target(link_target);

    if let Err(e) = symlink_file(&normalized, link_path) {
        eprintln!(
            "Warning: Failed to create symlink {} -> {}: {}",
            link_path.display(),
            normalized.display(),
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

    let normalized = normalize_symlink_target(link_target);

    if let Err(e) = symlink_dir(&normalized, link_path) {
        eprintln!(
            "Warning: Failed to create directory symlink {} -> {}: {}",
            link_path.display(),
            normalized.display(),
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

pub type Result<T> = anyhow::Result<T>;

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
            .ok_or_else(|| anyhow::anyhow!("Profile '{}' not found", profile_name))?;

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
            bail!("Circular dependency detected involving group '{}'", group_name);
        }

        in_stack.insert(group_name.to_string());

        let group = self
            .groups
            .get(group_name)
            .ok_or_else(|| anyhow::anyhow!("Group '{}' not found", group_name))?;

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

pub trait FileConsumer {
    fn add_file(&mut self, path: &Path, contents: &[u8], mode: u32) -> Result<()>;
    fn add_dir(&mut self, path: &Path) -> Result<()>;
    fn add_symlink(&mut self, path: &Path, target: &Path) -> Result<()>;
}

pub struct TarConsumer<W: Write> {
    builder: Builder<GzEncoder<W>>,
}

impl<W: Write> TarConsumer<W> {
    pub fn new(writer: W) -> Result<Self> {
        let encoder = GzEncoder::new(writer, Compression::default());
        let builder = Builder::new(encoder);
        Ok(Self {
            builder,
        })
    }
}

impl<W: Write> FileConsumer for TarConsumer<W> {
    fn add_file(&mut self, path: &Path, contents: &[u8], _mode: u32) -> Result<()> {
        let mut header = tar::Header::new_gnu();
        header.set_size(contents.len() as u64);
        header.set_mode(0o644);
        header.set_mtime(0);
        header.set_cksum();
        self.builder.append_data(&mut header, path, contents)?;
        Ok(())
    }

    fn add_dir(&mut self, path: &Path) -> Result<()> {
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o755);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::Directory);
        header.set_cksum();
        self.builder.append_data(&mut header, path, &[][..])?;
        Ok(())
    }

    fn add_symlink(&mut self, path: &Path, target: &Path) -> Result<()> {
        let mut header = tar::Header::new_gnu();
        header.set_size(0);
        header.set_mode(0o777);
        header.set_mtime(0);
        header.set_entry_type(tar::EntryType::Symlink);
        header.set_cksum();
        self.builder.append_link(&mut header, path, target)?;
        Ok(())
    }
}

impl<W: Write> TarConsumer<W> {
    pub fn finish(mut self) -> Result<()> {
        self.builder.finish()?;
        Ok(())
    }
}

pub struct ZipConsumer<W: Write + Seek> {
    writer: ZipWriter<W>,
}

impl<W: Write + Seek> ZipConsumer<W> {
    pub fn new(writer: W) -> Self {
        Self {
            writer: ZipWriter::new(writer),
        }
    }
}

impl<W: Write + Seek> FileConsumer for ZipConsumer<W> {
    fn add_file(&mut self, path: &Path, contents: &[u8], _mode: u32) -> Result<()> {
        let path_str = path.to_string_lossy().replace('\\', "/");
        self.writer.start_file(&path_str, SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated).unix_permissions(0o644))?;
        self.writer.write_all(contents)?;
        Ok(())
    }

    fn add_dir(&mut self, path: &Path) -> Result<()> {
        let path_str = path.to_string_lossy().replace('\\', "/");
        let dir_path = if path_str.ends_with('/') {
            path_str.to_string()
        } else {
            format!("{}/", path_str)
        };
        self.writer.add_directory(&dir_path, SimpleFileOptions::default().unix_permissions(0o755))?;
        Ok(())
    }

    fn add_symlink(&mut self, path: &Path, target: &Path) -> Result<()> {
        // ZIP doesn't natively support symlinks, so we store them as regular files
        // with the target path as content (Unix-style)
        let path_str = path.to_string_lossy().replace('\\', "/");
        let target_str = target.to_string_lossy();
        self.writer.start_file(&path_str, SimpleFileOptions::default().compression_method(zip::CompressionMethod::Deflated).unix_permissions(0o777))?;
        self.writer.write_all(target_str.as_bytes())?;
        Ok(())
    }
}

impl<W: Write + Seek> ZipConsumer<W> {
    pub fn finish(self) -> Result<()> {
        self.writer.finish()?;
        Ok(())
    }
}

pub struct DiskConsumer {
    output_dir: PathBuf,
    #[cfg(windows)]
    has_symlink_privileges: bool,
}

impl DiskConsumer {
    pub fn new(output_dir: PathBuf) -> Result<Self> {
        fs::create_dir_all(&output_dir)?;

        #[cfg(windows)]
        let has_symlink_privileges = has_symlink_privileges();

        Ok(Self {
            output_dir,
            #[cfg(windows)]
            has_symlink_privileges,
        })
    }
}

impl FileConsumer for DiskConsumer {
    fn add_file(&mut self, path: &Path, contents: &[u8], _mode: u32) -> Result<()> {
        let dest = self.output_dir.join(path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent)
                .with_context(|| format!("Failed to create directory tree for {}", parent.display()))?;
        }
        if !dest.exists() {
            fs::write(&dest, contents)
                .with_context(|| format!("Failed to write file to disk: {}", dest.display()))?;
        }
        Ok(())
    }

    fn add_dir(&mut self, path: &Path) -> Result<()> {
        let dest = self.output_dir.join(path);
        if dest.is_file() || dest.is_symlink() {
            fs::remove_file(&dest).with_context(|| format!("Failed to remove existing file at {}", dest.display()))?;
        }
        fs::create_dir_all(&dest).with_context(|| format!("Failed to create directory: {}", dest.display()))?;
        Ok(())
    }

    fn add_symlink(&mut self, path: &Path, target: &Path) -> Result<()> {
        let dest = self.output_dir.join(path);
        if let Some(parent) = dest.parent() {
            fs::create_dir_all(parent).context("Failed to create parent dir for symlink")?;
        }

        if dest.is_symlink() {
            if dest.is_dir() {
                fs::remove_dir_all(&dest).with_context(|| format!("Failed to clear dir for symlink: {}", dest.display()))?;
            } else {
                fs::remove_file(&dest).with_context(|| format!("Failed to clear file for symlink: {}", dest.display()))?;
            }
        } else if dest.exists() {
            return Ok(());
        }

        #[cfg(windows)]
        {
            // Note: Since DiskConsumer has logic here, I'm wrapping the inner Windows calls
            use std::os::windows::fs::{symlink_dir, symlink_file};
            if !self.has_symlink_privileges { return Ok(()); }
            let normalized_target = normalize_symlink_target(target);
            let mut actual_target_path = dest.parent().unwrap_or(&self.output_dir).to_path_buf();
            actual_target_path.push(target);

            let is_dir = fs::metadata(&actual_target_path).map(|m| m.is_dir()).unwrap_or(false);
            if is_dir {
                symlink_dir(&normalized_target, &dest).context("Failed Windows dir symlink")?;
            } else {
                symlink_file(&normalized_target, &dest).context("Failed Windows file symlink")?;
            }
        }

        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(target, &dest)
                .with_context(|| format!("Failed to create unix symlink: {} -> {}", dest.display(), target.display()))?;
        }
        Ok(())
    }
}

pub fn process_deb_into_consumer<C: FileConsumer>(deb_data: &[u8], consumer: &mut C, prefix: &str) -> Result<()> {
    let mut ar = ArArchive::new(deb_data);

    while let Some(entry_result) = ar.next_entry() {
        let mut entry = entry_result?;
        let name = String::from_utf8_lossy(entry.header().identifier()).to_string();

        if name.starts_with("data.tar") {
            let mut data = Vec::new();
            entry.read_to_end(&mut data)?;

            let decompressed = if name.ends_with(".gz") {
                let mut decoder = GzDecoder::new(&data[..]);
                let mut buf = Vec::new();
                decoder.read_to_end(&mut buf)?;
                buf
            } else if name.ends_with(".xz") {
                let mut decoder = XzDecoder::new(&data[..]);
                let mut buf = Vec::new();
                decoder.read_to_end(&mut buf)?;
                buf
            } else {
                data
            };

            return process_data_tar(&decompressed, consumer, prefix);
        }
    }
    bail!(io::Error::new(io::ErrorKind::InvalidData, "data.tar missing"))
}

fn process_data_tar<C: FileConsumer>(data_tar: &[u8], consumer: &mut C, prefix: &str) -> Result<()> {
    let mut archive = tar::Archive::new(data_tar);
    for entry in archive.entries()? {
        let mut entry = entry?;
        let path = entry.path()?;

        let rel_path = path.strip_prefix("/").unwrap_or(&path);
        let final_path = PathBuf::from(prefix).join(rel_path);

        match entry.header().entry_type() {
            tar::EntryType::Directory => consumer.add_dir(&final_path)?,
            tar::EntryType::Regular => {
                let mut buffer = Vec::new();
                entry.read_to_end(&mut buffer)?;
                consumer.add_file(&final_path, &buffer, entry.header().mode()?)?;
            }
            tar::EntryType::Symlink => {
                if let Some(link) = entry.link_name()? {
                    consumer.add_symlink(&final_path, &link)?;
                }
            }
            _ => {} // Handle other types if necessary
        }
    }
    Ok(())
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

    fn add_standard_links<C: FileConsumer>(&self, consumer: &mut C, prefix: &str) -> Result<()> {
        let links = [
            ("lib", "usr/lib"),
            ("lib64", "usr/lib64"),
            ("bin", "usr/bin"),
            ("sbin", "usr/sbin"),
        ];

        let prefix_path = Path::new(prefix);

        for (link_name, target_name) in links {
            let link_path = prefix_path.join(link_name);
            let target_path = Path::new(target_name);
            consumer.add_symlink(&link_path, target_path)?;
        }

        Ok(())
    }

    pub async fn build<C: FileConsumer>(&self, profile_name: &str, consumer: &mut C) -> Result<()> {
        println!("Resolving packages for profile '{}'...", profile_name);
        let package_names = self.config.resolve_packages(profile_name)?;
        println!("Found {} packages to process", package_names.len());

        let mut all_pkg_infos = Vec::new();
        for pkg_name in &package_names {
            all_pkg_infos.push(self.fetcher.fetch_package(pkg_name)?);
        }

        let to_download: Vec<PackageInfo> = all_pkg_infos
            .iter()
            .filter(|info| !self.cache.has_cached(&info.name, &info.version, &info.architecture))
            .cloned()
            .collect();

        if !to_download.is_empty() {
            println!("Downloading {} missing packages concurrently...", to_download.len());
            let concurrency = 8;
            let downloads = stream::iter(to_download)
                .map(|pkg_info| async move {
                    println!("  Downloading {} {}...", pkg_info.name, pkg_info.version);
                    let data = self.fetcher.download_package(&pkg_info).await?;
                    self.cache.save(&pkg_info.name, &pkg_info.version, &pkg_info.architecture, &data)?;
                    Ok::<(), anyhow::Error>(())
                })
                .buffer_unordered(concurrency);

            let mut results = downloads.collect::<Vec<_>>().await;
            for res in results.drain(..) {
                res?;
            }
        }

        for pkg_info in &all_pkg_infos {
            println!("Processing {}...", pkg_info.name);

            let deb_data = if self.cache.has_cached(&pkg_info.name, &pkg_info.version, &pkg_info.architecture) {
                self.cache.load(&pkg_info.name, &pkg_info.version, &pkg_info.architecture)?
            } else {
                // This shouldn't happen now, but just in case
                println!("  Downloading {} {}...", pkg_info.name, pkg_info.version);
                let data = self.fetcher.download_package(&pkg_info).await?;
                self.cache.save(&pkg_info.name, &pkg_info.version, &pkg_info.architecture, &data)?;
                data
            };

            process_deb_into_consumer(&deb_data, consumer, "sysroot")?;
        }

        println!("Creating standard sysroot symlinks...");
        self.add_standard_links(consumer, "sysroot")?;

        let package_list: Vec<String> = all_pkg_infos
            .iter()
            .map(|info| format!("{}={}", info.name, info.version))
            .collect();

        println!("Writing packages.txt into output...");
        let package_list_content = package_list.join("\n");
        consumer.add_file(
            Path::new("packages.txt"),
            package_list_content.as_bytes(),
            0o644
        )?;

        println!("Writing toolchain.cmake into output...");
        let toolchain_content = get_toolchain_content();
        consumer.add_file(
            Path::new("toolchain.cmake"),
            toolchain_content.as_bytes(),
            0o644
        )?;

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

    pub fn write_package_list(&self, output_dir: &Path, profile_name: &str) -> Result<()> {
        let package_names = self.config.resolve_packages(profile_name)?;

        let mut package_list = Vec::new();
        for pkg_name in &package_names {
            if let Ok(pkg_info) = self.fetcher.fetch_package(pkg_name) {
                package_list.push(format!("{}={}", pkg_info.name, pkg_info.version));
            }
        }

        let package_list_content = package_list.join("\n");
        let package_list_path = output_dir.join("packages.txt");
        fs::write(&package_list_path, package_list_content)?;
        println!("Package list written to: {}", package_list_path.display());
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
            cache_dir
        } => {
            let config = Config::load(&config)?;
            let mut builder = SysrootBuilder::new(config, arch, Some(cache_dir), !no_cache)?;

            builder.initialize().await?;

            let output_str = output.to_string_lossy();
            if output_str.ends_with(".tar.gz") || output_str.ends_with(".tgz") {
                let file = File::create(&output)?;
                let mut consumer = TarConsumer::new(file)?;
                builder.build(&profile, &mut consumer).await?;
                consumer.finish()?;
            } else if output_str.ends_with(".zip") {
                let file = File::create(&output)?;
                let mut consumer = ZipConsumer::new(file);
                builder.build(&profile, &mut consumer).await?;
                consumer.finish()?;
            } else {
                let mut consumer = DiskConsumer::new(output.clone())?;
                builder.build(&profile, &mut consumer).await?;
            }
            println!("Sysroot build complete: {}", output.display());
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

            let mut consumer = DiskConsumer::new(output.clone())?;

            builder.build(&profile, &mut consumer).await?;

            if toolchain {
                builder.write_toolchain_file(&output)?;
            }
            builder.write_package_list(&output, &profile)?;

            println!("Sysroot extracted to: {}", output.display());
        }
    }

    Ok(())
}

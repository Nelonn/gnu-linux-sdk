use crate::Result;
use std::fs::{self, File};
use std::io::Write;
use std::path::PathBuf;

#[derive(Debug, Clone)]
pub struct FileCache {
    cache_dir: PathBuf,
    enabled: bool,
}

impl FileCache {
    pub fn new(cache_dir: PathBuf, enabled: bool) -> Result<Self> {
        let cache_dir = if cache_dir.is_absolute() {
            cache_dir
        } else {
            std::env::current_dir()?.join(cache_dir)
        };
        Ok(Self { cache_dir, enabled })
    }

    pub fn get_path(&self, pkg_name: &str, pkg_version: &str, pkg_architecture: &str) -> PathBuf {
        let safe_version = pkg_version.replace(':', "_").replace('/', "_");
        self.cache_dir.join(format!("{}_{}_{}.deb", pkg_name, safe_version, pkg_architecture))
    }

    pub fn has_cached(&self, pkg_name: &str, pkg_version: &str, pkg_architecture: &str) -> bool {
        self.enabled && self.get_path(pkg_name, pkg_version, pkg_architecture).exists()
    }

    pub fn save(&self, pkg_name: &str, pkg_version: &str, pkg_architecture: &str, data: &[u8]) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        fs::create_dir_all(&self.cache_dir)?;
        let path = self.get_path(pkg_name, pkg_version, pkg_architecture);
        let mut file = File::create(&path)?;
        file.write_all(data)?;
        Ok(())
    }

    pub fn load(&self, pkg_name: &str, pkg_version: &str, pkg_architecture: &str) -> Result<Vec<u8>> {
        let path = self.get_path(pkg_name, pkg_version, pkg_architecture);
        Ok(fs::read(&path)?)
    }
}

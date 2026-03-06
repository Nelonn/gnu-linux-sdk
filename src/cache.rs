use crate::{Result, SysrootError};
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

    pub fn get_path(&self, pkg_name: &str, pkg_version: &str) -> PathBuf {
        // Use name_version as cache key to handle multiple versions
        let safe_version = pkg_version.replace(':', "_").replace('/', "_");
        self.cache_dir.join(format!("{}_{}.deb", pkg_name, safe_version))
    }

    pub fn has_cached(&self, pkg_name: &str, pkg_version: &str) -> bool {
        self.enabled && self.get_path(pkg_name, pkg_version).exists()
    }

    pub fn save(&self, pkg_name: &str, pkg_version: &str, data: &[u8]) -> Result<()> {
        if !self.enabled {
            return Ok(());
        }
        fs::create_dir_all(&self.cache_dir)?;
        let path = self.get_path(pkg_name, pkg_version);
        let mut file = File::create(&path)?;
        file.write_all(data)?;
        Ok(())
    }

    pub fn load(&self, pkg_name: &str, pkg_version: &str) -> Result<Vec<u8>> {
        let path = self.get_path(pkg_name, pkg_version);
        fs::read(&path).map_err(SysrootError::from)
    }
}

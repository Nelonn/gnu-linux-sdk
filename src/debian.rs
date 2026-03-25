use crate::{PackageInfo, Result};
use flate2::read::GzDecoder;
use reqwest::Client;
use std::collections::HashMap;
use std::io::Read;
use xz2::read::XzDecoder;
use anyhow::bail;

pub struct DebianFetcher {
    client: Client,
    suite: String,
    architecture: String,
    mirrors: Vec<String>,
    components: Vec<String>,
    /// Cached package index: package name -> package info
    package_index: Option<HashMap<String, PackageInfo>>,
}

impl DebianFetcher {
    pub fn new(suite: String, architecture: String, mirrors: Vec<String>, components: Vec<String>) -> Self {
        Self {
            client: Client::new(),
            suite,
            architecture,
            mirrors,
            components,
            package_index: None,
        }
    }

    pub async fn initialize(&mut self) -> Result<()> {
        if self.package_index.is_some() {
            return Ok(());
        }

        eprintln!("Fetching package index...");
        for mirror in &self.mirrors {
            eprintln!("  Mirror: {}", mirror);
            if let Some(index) = self.fetch_index_from_mirror(mirror).await? {
                eprintln!("  Loaded {} packages from {}", index.len(), mirror);
                self.package_index = Some(index);
                return Ok(());
            }
        }

        bail!("Failed to fetch package index from any mirror")
    }

    async fn fetch_index_from_mirror(
        &self,
        mirror: &str,
    ) -> Result<Option<HashMap<String, PackageInfo>>> {
        let suite = &self.suite;
        let arch = &self.architecture;

        let mut paths = Vec::new();

        for component in &self.components {
            let compressions = ["", ".gz", ".xz"];
            for comp in compressions {
                paths.push(format!(
                    "dists/{}/{}/binary-{}/Packages{}",
                    suite, component, arch, comp
                ));
                if arch == "amd64" || arch == "i386" {
                    paths.push(format!(
                        "dists/{}/{}/binary-all/Packages{}",
                        suite, component, comp
                    ));
                }
            }
        }

        for path in &paths {
            let url = format!("{}/{}", mirror.trim_end_matches('/'), path);

            let response = self.client.get(&url).send().await;

            if let Ok(resp) = response {
                if resp.status().is_success() {
                    let bytes = resp.bytes().await?;
                    let content = if path.ends_with(".gz") {
                        let mut decoder = GzDecoder::new(&bytes[..]);
                        let mut decompressed = Vec::new();
                        if decoder.read_to_end(&mut decompressed).is_err() {
                            continue;
                        }
                        String::from_utf8_lossy(&decompressed).to_string()
                    } else if path.ends_with(".xz") {
                        let mut decoder = XzDecoder::new(&bytes[..]);
                        let mut decompressed = Vec::new();
                        if decoder.read_to_end(&mut decompressed).is_err() {
                            continue;
                        }
                        String::from_utf8_lossy(&decompressed).to_string()
                    } else {
                        String::from_utf8_lossy(&bytes).to_string()
                    };

                    let index = self.parse_packages_index(&content, mirror);
                    if !index.is_empty() {
                        return Ok(Some(index));
                    }
                }
            }
        }

        Ok(None)
    }

    fn parse_packages_index(
        &self,
        content: &str,
        mirror: &str,
    ) -> HashMap<String, PackageInfo> {
        let mut index = HashMap::new();
        let mut current_pkg: Option<(String, String, String)> = None; // name, version, arch
        let mut current_filename = String::new();
        let mut package_count = 0;

        for line in content.lines() {
            if line.is_empty() {
                if let Some((pkg_name, version, arch)) = current_pkg.take() {
                    if (arch == self.architecture || arch == "all") && !current_filename.is_empty() {
                        let mirror_url = mirror.trim_end_matches('/');
                        index.insert(
                            pkg_name.clone(),
                            PackageInfo {
                                name: pkg_name,
                                version,
                                architecture: arch,
                                download_url: format!(
                                    "{}/{}",
                                    mirror_url,
                                    current_filename.trim_start_matches('/')
                                ),
                                filename: current_filename.clone(),
                            },
                        );
                        package_count += 1;
                    }
                }
                current_filename.clear();
                continue;
            }

            if line.starts_with(' ') {
                continue;
            }

            if let Some(rest) = line.strip_prefix("Package: ") {
                current_pkg = Some((rest.to_string(), String::new(), String::new()));
            } else if let Some(rest) = line.strip_prefix("Version: ") {
                if let Some(ref mut pkg) = current_pkg {
                    pkg.1 = rest.to_string();
                }
            } else if let Some(rest) = line.strip_prefix("Architecture: ") {
                if let Some(ref mut pkg) = current_pkg {
                    pkg.2 = rest.to_string();
                }
            } else if let Some(rest) = line.strip_prefix("Filename: ") {
                current_filename = rest.to_string();
            }
        }

        if let Some((pkg_name, version, arch)) = current_pkg {
            if (arch == self.architecture || arch == "all") && !current_filename.is_empty() {
                let mirror_url = mirror.trim_end_matches('/');
                index.insert(
                    pkg_name.clone(),
                    PackageInfo {
                        name: pkg_name,
                        version,
                        architecture: arch,
                        download_url: format!(
                            "{}/{}",
                            mirror_url,
                            current_filename.trim_start_matches('/')
                        ),
                        filename: current_filename,
                    },
                );
                package_count += 1;
            }
        }

        eprintln!("  Parsed {} packages for architecture {}", package_count, self.architecture);
        index
    }

    pub fn fetch_package(&self, package: &str) -> Result<PackageInfo> {
        match &self.package_index {
            Some(index) => index
                .get(package)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("Package not found: {}", package)),
            None => bail!("Package index not initialized. Call initialize() first."),
        }
    }

    pub async fn download_package(&self, pkg: &PackageInfo) -> Result<Vec<u8>> {
        let response = self.client.get(&pkg.download_url).send().await?;

        if !response.status().is_success() {
            bail!("Failed to download {}: HTTP {}", pkg.name, response.status());
        }

        let bytes = response.bytes().await?;
        Ok(bytes.to_vec())
    }
}

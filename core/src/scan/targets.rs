use std::path::{Path, PathBuf};

#[derive(Clone, Copy, Debug, PartialEq)]
pub enum ScanPreset {
    Quick,
    Full,
    RiskySpots,
}

fn env_path(variable: &str) -> Option<PathBuf> {
    std::env::var_os(variable)
        .map(PathBuf::from)
        .filter(|path| path.exists())
}

fn startup_path(base: &Path) -> PathBuf {
    base.join("Microsoft")
        .join("Windows")
        .join("Start Menu")
        .join("Programs")
        .join("Startup")
}

pub fn risky_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    for variable in ["TEMP", "APPDATA", "LOCALAPPDATA", "USERPROFILE"] {
        if let Some(path) = env_path(variable) {
            if variable == "USERPROFILE" {
                let downloads = path.join("Downloads");
                if downloads.exists() {
                    roots.push(downloads);
                }
            } else {
                if variable == "APPDATA" {
                    let startup = startup_path(&path);
                    if startup.exists() {
                        roots.push(startup);
                    }
                }
                roots.push(path);
            }
        }
    }

    if let Some(program_data) = env_path("PROGRAMDATA") {
        let startup = startup_path(&program_data);
        if startup.exists() {
            roots.push(startup);
        }
    }

    for fixed_path in [r"C:\Windows\Temp", r"C:\Windows\System32"] {
        let path = PathBuf::from(fixed_path);
        if path.exists() {
            roots.push(path);
        }
    }

    roots
}

pub fn full_roots() -> Vec<PathBuf> {
    let mut roots = Vec::new();

    for letter in b'A'..=b'Z' {
        let path = PathBuf::from(format!("{}:\\", letter as char));
        if path.exists() {
            roots.push(path);
        }
    }

    roots
}

pub fn roots_for(preset: ScanPreset) -> Vec<PathBuf> {
    match preset {
        ScanPreset::Quick | ScanPreset::RiskySpots => risky_roots(),
        ScanPreset::Full => full_roots(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn preset_maps_do_not_panic() {
        let _ = roots_for(ScanPreset::Quick);
        let _ = roots_for(ScanPreset::RiskySpots);
        let _ = roots_for(ScanPreset::Full);
    }

    #[test]
    fn quick_equals_risky_for_phase_one() {
        assert_eq!(
            roots_for(ScanPreset::Quick),
            roots_for(ScanPreset::RiskySpots)
        );
    }

    #[test]
    fn startup_path_uses_windows_startup_relative_layout() {
        let base = Path::new("base");

        assert_eq!(
            startup_path(base),
            base.join("Microsoft")
                .join("Windows")
                .join("Start Menu")
                .join("Programs")
                .join("Startup")
        );
    }
}

//! Where Arke keeps its files: the profile folders, or one folder beside the exe.
//!
//! Portable mode turns on when a file named `portable` sits next to the exe. Every data file
//! (settings, folder views, workspaces, shelf, search history, host keys, the search index, the
//! log and downloaded updates) then lives in `<exe folder>\data`, so the whole app can be carried
//! on a USB stick or moved without leaving anything behind in the profile. Without the marker the
//! original `%APPDATA%\Arke` and `%LOCALAPPDATA%\Arke` are used.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;

/// Marker file, next to the exe, that turns on portable mode.
const PORTABLE_MARKER: &str = "portable";

/// Folder, next to the exe, that holds every data file in portable mode.
const PORTABLE_DATA_DIR: &str = "data";

/// The folder the running exe sits in.
fn exe_dir() -> Option<PathBuf> {
    std::env::current_exe()
        .ok()?
        .parent()
        .map(Path::to_path_buf)
}

/// Whether the marker file is next to the exe. Cached: the exe does not move while running.
pub(crate) fn portable() -> bool {
    static FOUND: OnceLock<bool> = OnceLock::new();
    *FOUND.get_or_init(|| exe_dir().is_some_and(|dir| dir.join(PORTABLE_MARKER).exists()))
}

/// `<exe folder>\data` in portable mode, else `None`.
pub(crate) fn portable_data_dir() -> Option<PathBuf> {
    if portable() {
        exe_dir().map(|dir| dir.join(PORTABLE_DATA_DIR))
    } else {
        None
    }
}

/// Where settings and the files next to them live: `%APPDATA%\Arke`, or the portable data folder.
pub(crate) fn settings_dir() -> Option<PathBuf> {
    portable_data_dir().or_else(|| {
        std::env::var_os("APPDATA").map(|dir| PathBuf::from(dir).join("Arke"))
    })
}

/// Where the index, log and downloads live: `%LOCALAPPDATA%\Arke`, or the portable data folder.
pub(crate) fn cache_dir() -> Option<PathBuf> {
    portable_data_dir().or_else(|| {
        std::env::var_os("LOCALAPPDATA").map(|dir| PathBuf::from(dir).join("Arke"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The test exe lives in a build folder with no marker, so the profile folders apply.
    #[test]
    fn a_missing_marker_keeps_the_profile_folders() {
        assert!(!portable());
        assert!(portable_data_dir().is_none());
        let settings = settings_dir().expect("APPDATA");
        assert!(settings.ends_with("Arke"));
        let cache = cache_dir().expect("LOCALAPPDATA");
        assert!(cache.ends_with("Arke"));
    }
}

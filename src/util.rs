/*
 * Copyright 2023 Trevor Bentley
 *
 * Author: Trevor Bentley
 * Contact: gitsy@@trevorbentley.com
 * Source: https://github.com/mrmekon/itsy-gitsy
 *
 * This file is part of Itsy-Gitsy.
 *
 * Itsy-Gitsy is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * Itsy-Gitsy is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with Itsy-Gitsy.  If not, see <http://www.gnu.org/licenses/>.
 */
use glob::glob;
use std::error::Error as StdError;
use std::path::Path;
use std::path::PathBuf;
use std::sync::atomic::AtomicUsize;

pub static VERBOSITY: AtomicUsize = AtomicUsize::new(0);

#[macro_export]
#[allow(unused_macros)]
macro_rules! always {
    () => { println!() };
    ($($arg:tt)*) => {{ println!($($arg)*); }};
}

#[macro_export]
#[allow(unused_macros)]
macro_rules! error {
    () => { eprintln!() };
    ($($arg:tt)*) => {{ eprintln!($($arg)*); }};
}

#[macro_export]
#[allow(unused_macros)]
macro_rules! normal {
    () => { if crate::util::VERBOSITY.load(Ordering::Relaxed) > 0 { println!() } };
    ($($arg:tt)*) => {{ if crate::util::VERBOSITY.load(Ordering::Relaxed) > 0 { println!($($arg)*); } }};
}

#[macro_export]
#[allow(unused_macros)]
macro_rules! normal_noln {
    () => { if crate::util::VERBOSITY.load(Ordering::Relaxed) > 0 { print!(); let _ = std::io::stdout().flush(); } };
    ($($arg:tt)*) => { if crate::util::VERBOSITY.load(Ordering::Relaxed) > 0 { {print!($($arg)*);}; let _ = std::io::stdout().flush(); }};
}

#[macro_export]
#[allow(unused_macros)]
macro_rules! loud {
    () => { if crate::util::VERBOSITY.load(Ordering::Relaxed) > 1 { println!() } };
    ($($arg:tt)*) => {{ if crate::util::VERBOSITY.load(Ordering::Relaxed) > 1 { println!($($arg)*); } }};
}

#[macro_export]
#[allow(unused_macros)]
macro_rules! louder {
    () => { if crate::util::VERBOSITY.load(Ordering::Relaxed) > 2 { println!() } };
    ($($arg:tt)*) => {{ if crate::util::VERBOSITY.load(Ordering::Relaxed) > 2 { println!($($arg)*); } }};
}

#[macro_export]
#[allow(unused_macros)]
macro_rules! loudest {
    () => { if crate::util::VERBOSITY.load(Ordering::Relaxed) > 3 { println!() } };
    ($($arg:tt)*) => {{ if crate::util::VERBOSITY.load(Ordering::Relaxed) > 3 { println!($($arg)*); } }};
}

#[derive(Default, Clone)]
#[allow(dead_code)]
pub enum GitsyErrorKind {
    #[default]
    Unknown,
    Settings,
    Template,
    Git,
    Filesystem,
}

#[derive(Default)]
pub struct GitsyError {
    msg: Option<String>,
    kind: GitsyErrorKind,
    source: Option<Box<dyn std::error::Error>>,
}
unsafe impl Send for GitsyError {}

impl Clone for GitsyError {
    fn clone(&self) -> Self {
        GitsyError {
            msg: self.msg.clone(),
            kind: self.kind.clone(),
            source: None,
        }
    }
}

#[allow(dead_code)]
impl GitsyError {
    pub fn kind(kind: GitsyErrorKind, msg: Option<&str>) -> Self {
        GitsyError {
            kind,
            msg: msg.map(|x| x.to_owned()),
            source: None,
        }
    }
    pub fn sourced_kind(kind: GitsyErrorKind, msg: Option<&str>, source: impl std::error::Error + 'static) -> Self {
        GitsyError {
            kind,
            msg: msg.map(|x| x.to_owned()),
            source: Some(Box::new(source)),
        }
    }
}
impl std::fmt::Display for GitsyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            GitsyErrorKind::Git => write!(f, "gitsy error (git)")?,
            GitsyErrorKind::Settings => write!(f, "gitsy error (settings)")?,
            GitsyErrorKind::Template => write!(f, "gitsy error (template)")?,
            GitsyErrorKind::Filesystem => write!(f, "gitsy error (filesystem)")?,
            GitsyErrorKind::Unknown => write!(f, "gitsy error (unknown)")?,
        }
        write!(f, ": {}", self.msg.as_deref().unwrap_or_default())?;
        if let Some(src) = &self.source {
            write!(f, " ({})", src)?;
        }
        Ok(())
    }
}
impl std::fmt::Debug for GitsyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}
impl std::error::Error for GitsyError {
    fn source(&self) -> Option<&(dyn StdError + 'static)> {
        self.source.as_ref().map(|c| &**c as &(dyn StdError + 'static))
    }
}
impl From<git2::Error> for GitsyError {
    fn from(source: git2::Error) -> Self {
        GitsyError::sourced_kind(GitsyErrorKind::Git, Some(&source.message().to_owned()), source)
    }
}
impl From<tera::Error> for GitsyError {
    fn from(source: tera::Error) -> Self {
        GitsyError::sourced_kind(GitsyErrorKind::Template, Some(&source.to_string()), source)
    }
}

pub fn sanitize_path_component(var: &str) -> String {
    let nasty_chars = r###"<>:"/\|?*&"###.to_string() + "\n\t\0";
    let mut safe_str = var.to_string();
    safe_str.retain(|c| !nasty_chars.contains(c));
    safe_str
}

pub fn urlify_path(path: &str) -> String {
    let path = path.replace("/", "+").replace("\\", "+");
    path.trim().to_string()
}

pub trait SafePathVar {
    fn safe_substitute(&self, path: &impl AsRef<Path>) -> PathBuf;
}

// src is a regular file, dst is a directory to copy into
pub fn copy_file<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q) -> Result<(), GitsyError> {
    let (src, dst) = (src.as_ref(), dst.as_ref());
    if !dst.is_dir() {
        return Err(GitsyError::kind(
            GitsyErrorKind::Filesystem,
            Some(&format!(
                "Copy failed, destination is not a directory: {}",
                dst.display()
            )),
        ));
    }
    if src.is_dir() {
        return Err(GitsyError::kind(
            GitsyErrorKind::Filesystem,
            Some(&format!("Copy failed, source is not a regular file: {}", src.display())),
        ));
    }
    let filename = src.file_name().ok_or(GitsyError::kind(
        GitsyErrorKind::Filesystem,
        Some(&format!("Can't determine filename to copy file: {}", src.display())),
    ))?;
    let mut target = dst.to_owned();
    target.push(filename);
    std::fs::copy(&src, &target).map_err(|e| GitsyError::kind(GitsyErrorKind::Filesystem, Some(&e.to_string())))?;
    Ok(())
}

// src is a directory, dst is a directory to copy into.
// returns an error if any files in src are directories and 'recurse' is not true.
pub fn copy_dir<P: AsRef<Path>, Q: AsRef<Path>>(src: P, dst: Q, recurse: bool) -> Result<(), GitsyError> {
    let (src, mut dst) = (src.as_ref(), dst.as_ref().to_owned());
    if !src.is_dir() {
        return Err(GitsyError::kind(
            GitsyErrorKind::Filesystem,
            Some(&format!("Copy failed, source is not a directory: {}", src.display())),
        ));
    }
    if !dst.is_dir() {
        return Err(GitsyError::kind(
            GitsyErrorKind::Filesystem,
            Some(&format!(
                "Copy failed, destination is not a directory: {}",
                dst.display()
            )),
        ));
    }

    let dir_name = src.file_name().ok_or(GitsyError::kind(
        GitsyErrorKind::Filesystem,
        Some(&format!("Can't determine directory to copy from: {}", src.display())),
    ))?;
    dst.push(dir_name);
    std::fs::create_dir(&dst).map_err(|_e| {
        GitsyError::kind(
            GitsyErrorKind::Filesystem,
            Some(&format!("Unable to create destination directory: {}", dst.display())),
        )
    })?;

    let mut all_glob = src.to_owned();
    all_glob.push("*");
    for entry in glob(all_glob.to_str().ok_or(GitsyError::kind(
        GitsyErrorKind::Filesystem,
        Some(&format!("Unable to list files in source directory: {}", src.display())),
    ))?)
    .map_err(|_e| {
        GitsyError::kind(
            GitsyErrorKind::Filesystem,
            Some(&format!("Unable to list files in source directory: {}", src.display())),
        )
    })? {
        let entry = entry.map_err(|_e| {
            GitsyError::kind(
                GitsyErrorKind::Filesystem,
                Some(&format!("Unable to list files in source directory: {}", src.display())),
            )
        })?;
        match entry.is_dir() {
            true => match recurse {
                true => copy_dir(&entry, &dst, recurse)?,
                false => {
                    return Err(GitsyError::kind(
                        GitsyErrorKind::Filesystem,
                        Some(&format!("Cannot copy, source is a directory: {}", src.display())),
                    ))
                }
            },
            false => {
                copy_file(&entry, &dst)?;
            }
        }
    }
    Ok(())
}

// src is a file or directory, dst is a directory to copy into
// returns an error if src is a directory and 'recurse' is not true.
#[allow(dead_code)]
pub fn copy<P: AsRef<Path>>(src: P, dst: P, recurse: bool) -> Result<(), GitsyError> {
    let (src, dst) = (src.as_ref(), dst.as_ref());
    match src.is_dir() {
        true => match recurse {
            true => copy_dir(src, dst, recurse),
            false => Err(GitsyError::kind(
                GitsyErrorKind::Filesystem,
                Some(&format!("Cannot copy, source is a directory: {}", src.display())),
            )),
        },
        false => copy_file(src, dst),
    }
}

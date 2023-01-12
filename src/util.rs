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

#[allow(dead_code)]
pub enum GitsyErrorKind {
    Unknown,
    Settings,
    Template,
    Git,
}
pub struct GitsyError {
    msg: Option<String>,
    kind: GitsyErrorKind,
    source: Option<Box<dyn std::error::Error>>,
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
            _ => write!(f, "gitsy error (unknown)")?,
        }
        write!(f, ": {}", self.msg.as_deref().unwrap_or_default())
    }
}
impl std::fmt::Debug for GitsyError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self)
    }
}
impl std::error::Error for GitsyError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_deref()
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

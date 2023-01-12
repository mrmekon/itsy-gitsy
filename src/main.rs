use chrono::{
    DateTime,
    offset::FixedOffset,
    naive::NaiveDateTime,
};
use clap::Parser;
use git2::{DiffOptions, Repository, Error};
use serde::{Serialize, Deserialize};
use std::cell::RefCell;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::cmp;
use std::fs::{File, create_dir, create_dir_all, read_dir, read_to_string};
use std::hash::{Hash, Hasher};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tera::{Context, Filter, Function, Tera, Value, to_value, try_get_value};

#[cfg(feature = "markdown")]
use pulldown_cmark::{html, Options, Parser as MdParser};

#[cfg(any(feature = "highlight", feature = "highlight_fast"))]
use syntect::{
    html::{ClassedHTMLGenerator, ClassStyle, css_for_theme_with_class_style},
    parsing::SyntaxSet,
    highlighting::ThemeSet,
    util::LinesWithEndings,
};

static VERBOSITY: AtomicUsize = AtomicUsize::new(0);

#[allow(unused_macros)]
macro_rules! always {
    () => { println!() };
    ($($arg:tt)*) => {{ println!($($arg)*); }};
}
#[allow(unused_macros)]
macro_rules! error {
    () => { eprintln!() };
    ($($arg:tt)*) => {{ eprintln!($($arg)*); }};
}
#[allow(unused_macros)]
macro_rules! normal {
    () => { if VERBOSITY.load(Ordering::Relaxed) > 0 { println!() } };
    ($($arg:tt)*) => {{ if VERBOSITY.load(Ordering::Relaxed) > 0 { println!($($arg)*); } }};
}
#[allow(unused_macros)]
macro_rules! normal_noln {
    () => { if VERBOSITY.load(Ordering::Relaxed) > 0 { print!(); let _ = std::io::stdout().flush(); } };
    ($($arg:tt)*) => { if VERBOSITY.load(Ordering::Relaxed) > 0 { {print!($($arg)*);}; let _ = std::io::stdout().flush(); }};
}
#[allow(unused_macros)]
macro_rules! loud {
    () => { if VERBOSITY.load(Ordering::Relaxed) > 1 { println!() } };
    ($($arg:tt)*) => {{ if VERBOSITY.load(Ordering::Relaxed) > 1 { println!($($arg)*); } }};
}
#[allow(unused_macros)]
macro_rules! louder {
    () => { if VERBOSITY.load(Ordering::Relaxed) > 2 { println!() } };
    ($($arg:tt)*) => {{ if VERBOSITY.load(Ordering::Relaxed) > 2 { println!($($arg)*); } }};
}
#[allow(unused_macros)]
macro_rules! loudest {
    () => { if VERBOSITY.load(Ordering::Relaxed) > 3 { println!() } };
    ($($arg:tt)*) => {{ if VERBOSITY.load(Ordering::Relaxed) > 3 { println!($($arg)*); } }};
}

// TODO:
//
//   * pagination
//   * basic, light, dark, and fancy default themes
//   * split into modules
//   * parallelize output generation
//   * automated tests
//   * documentation + examples
//

fn ts_to_date(ts: i64, offset: Option<i64>, format: Option<String>) -> String {
    let offset = offset.unwrap_or(0);
    let dt = NaiveDateTime::from_timestamp_opt(ts + offset, 0).expect("Invalid timestamp");
    let dt_tz: DateTime<FixedOffset> = DateTime::from_local(dt, FixedOffset::east_opt(offset as i32).expect("Invalid timezone"));
    match format {
        Some(f) => dt_tz.format(&f).to_string(),
        None => dt_tz.format("%Y-%m-%d").to_string(),
    }
}

fn ts_to_git_timestamp(ts: i64, offset: Option<i64>) -> String {
    let offset = offset.unwrap_or(0);
    let dt = chrono::naive::NaiveDateTime::from_timestamp_opt(ts + offset, 0).expect("invalid timestamp");
    let dt_tz: DateTime<FixedOffset> = DateTime::from_local(dt, FixedOffset::east_opt(offset as i32).expect("Invalid timezone"));
    dt_tz.format("%a %b %e %T %Y %z").to_string()
}

fn first_line(msg: &[u8]) -> String {
    let message = String::from_utf8_lossy(msg);
    message.lines().next().unwrap_or("[no commit message]").to_owned()
}

#[derive(Serialize)]
struct GitRepo {
    name: String,
    metadata: GitsyMetadata,
    history: Vec<GitObject>,
    branches: Vec<GitObject>,
    tags: Vec<GitObject>,
    root_files: Vec<GitFile>,
    all_files: Vec<GitFile>,
    commits: BTreeMap<String, GitObject>,
}

#[derive(Serialize, Default)]
struct GitsyMetadata {
    full_name: Option<String>,
    description: Option<String>,
    website: Option<String>,
    clone: Option<String>,
    attributes: BTreeMap<String, toml::Value>,
}

#[derive(Serialize, Default)]
struct GitAuthor {
    name: Option<String>,
    email: Option<String>,
}

#[derive(Serialize, Default)]
struct GitObject {
    full_hash: String,
    short_hash: String,
    ts_utc: i64,
    ts_offset: i64,
    author: GitAuthor,
    committer: GitAuthor,
    parents: Vec<String>,
    ref_name: Option<String>,
    alt_refs: Vec<String>,
    tagged_id: Option<String>,
    tree_id: Option<String>,
    summary: Option<String>,
    message: Option<String>,
    stats: Option<GitStats>,
    diff: Option<GitDiffCommit>,
}

#[derive(Serialize, Default)]
struct GitStats {
    files: usize,
    additions: usize,
    deletions: usize,
}

#[derive(Serialize, Deserialize, Clone)]
struct GitFile {
    id: String,
    name: String,
    path: String,
    mode: i32,
    kind: String,
    is_binary: bool,
    size: usize,
    tree_depth: usize,
    contents: Option<String>,
    contents_safe: bool,
    contents_preformatted: bool,
}

#[derive(Serialize, Default)]
struct GitDiffCommit {
    files: Vec<GitDiffFile>,
    file_count: usize,
    additions: usize,
    deletions: usize,
}

#[derive(Serialize, Default)]
struct GitDiffFile {
    oldfile: String,
    newfile: String,
    basefile: String,
    oldid: String,
    newid: String,
    extra: String,
    additions: usize,
    deletions: usize,
    hunks: Vec<GitDiffHunk>
}

#[derive(Serialize, Default)]
struct GitDiffHunk {
    context: String,
    lines: Vec<GitDiffLine>,
}

#[derive(Serialize)]
struct GitDiffLine {
    kind: &'static str,
    prefix: &'static str,
    text: String,
}

fn walk_file_tree(repo: &git2::Repository, rev: &str, files: &mut Vec<GitFile>,
                  depth: usize, max_depth: usize, recurse: bool, prefix: &str) -> Result<(), Error> {
    let obj = repo.revparse_single(rev)?;
    let tree = obj.peel_to_tree()?;
    for entry in tree.iter() {
        let name = entry.name().unwrap_or_default().to_string();
        let path = prefix.to_string() + entry.name().unwrap_or_default();
        let kind = match entry.kind() {
            Some(git2::ObjectType::Tree) => "dir",
            Some(git2::ObjectType::Blob) => "file",
            Some(git2::ObjectType::Commit) => "submodule",
            _ => "unknown",
        };
        let mut is_binary = false;
        let mut size = 0;

        if let Ok(blob) = repo.find_blob(entry.id()) {
            is_binary = blob.is_binary();
            size = blob.content().len();
        }

        loudest!("   + file: {}", path);
        files.push(GitFile {
            id: entry.id().to_string(),
            name: name.clone(),
            path: path.clone(),
            kind: kind.to_string(),
            mode: entry.filemode(),
            is_binary,
            size,
            tree_depth: depth,
            contents: None,
            contents_safe: false,
            contents_preformatted: true,
        });
        if recurse && depth < (max_depth - 1) && entry.kind() == Some(git2::ObjectType::Tree) {
            let prefix = path + "/";
            walk_file_tree(repo, &entry.id().to_string(), files,
                           depth+1, max_depth, true, &prefix)?;
        }
    }
    Ok(())
}

fn parse_repo(repo: &Repository, name: &str, settings: &GitsySettingsRepo, metadata: GitsyMetadata) -> Result<GitRepo, Error> {
    let mut history: Vec<GitObject> = vec!();
    let mut branches: Vec<GitObject> = vec!();
    let mut tags: Vec<GitObject> = vec!();
    let mut commits: BTreeMap<String, GitObject> = BTreeMap::new();
    let mut commit_count = 0;
    let mut history_count = 0;
    let mut branch_count = 0;
    let mut tag_count = 0;

    // Cache the shortnames of all references
    let mut references: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for refr in repo.references()? {
        let refr = refr?;
        if let (Some(target), Some(name)) = (refr.target(), refr.shorthand()) {
            let id = target.to_string();
            match references.contains_key(&id) {
                false => { references.insert(target.to_string(), vec!(name.to_string())); },
                true => { references.get_mut(&id).unwrap().push(name.to_string()); },
            }
        }
    }

    loud!();
    let mut revwalk = repo.revwalk()?;
    revwalk.set_sorting(git2::Sort::TOPOLOGICAL)?;
    revwalk.push_head()?;
    loudest!(" - Parsing history:");
    for oid in revwalk {
        let oid = oid?;
        if commit_count >= settings.limit_commits.unwrap_or(usize::MAX) ||
            history_count >= settings.limit_history.unwrap_or(usize::MAX) {
                break;
        }
        commits.insert(oid.to_string(), parse_commit(repo, &oid.to_string())?);
        commit_count += 1;
        let commit = repo.find_commit(oid)?;
        let obj = repo.revparse_single(&commit.id().to_string())?;
        let full_hash = commit.id().to_string();
        let short_hash = obj.short_id()?.as_str().unwrap_or_default().to_string();

        let mut parents: Vec<String> = vec!();
        let a = if commit.parents().len() == 1 {
            let parent = commit.parent(0)?;
            parents.push(parent.id().to_string());
            Some(parent.tree()?)
        } else {
            None
        };
        let b = commit.tree()?;
        let mut diffopts = DiffOptions::new();
        let diff = repo.diff_tree_to_tree(a.as_ref(), Some(&b), Some(&mut diffopts))?;
        let stats = diff.stats()?;
        let stats = GitStats {
            files: stats.files_changed(),
            additions: stats.insertions(),
            deletions: stats.deletions(),
        };

        let alt_refs: Vec<String> = references.get(&commit.id().to_string())
            .map(|x| x.to_owned()).unwrap_or_default();

        if history_count < settings.limit_history.unwrap_or(usize::MAX) {
            loudest!("   + {} {}", full_hash, first_line(commit.message_bytes()));
            // TODO: this is basically a duplicate of the commit
            // array, and really should be pointers to that array
            // instead.  But it's not a quick task to switch to
            // self-referential data structures in Rust.
            history.push(GitObject {
                full_hash,
                short_hash,
                ts_utc: commit.author().when().seconds(),
                ts_offset: (commit.author().when().offset_minutes() as i64) * 60,
                parents,
                ref_name: None,
                alt_refs,
                author: GitAuthor {
                    name:  commit.author().name().map(|x| x.to_owned()),
                    email: commit.author().email().map(|x| x.to_owned()),
                },
                summary: Some(first_line(commit.message_bytes())),
                stats: Some(stats),
                ..Default::default()
            });
            history_count += 1;
        }
    }
    loud!(" - parsed {} history entries", history_count);
    loud!(" - parsed {} commits", commit_count);

    loudest!(" - Parsing branches:");
    for branch in repo.branches(None)? {
        if branch_count >= settings.limit_branches.unwrap_or(usize::MAX) {
            break;
        }
        let (branch, _branch_type) = branch?;
        let refr = branch.get();
        let name = branch.name()?.unwrap_or("[unnamed]");
        let obj = repo.revparse_single(name)?;
        // Only show direct references, skip symbolic aliases.  Maybe
        // this is a bad idea?
        match refr.kind() {
            Some(k) if k == git2::ReferenceType::Symbolic => continue,
            _ => {},
        }
        let commit = repo.find_commit(obj.id())?;
        let full_hash = obj.id().to_string();
        let short_hash = obj.short_id()?.as_str().unwrap_or_default().to_string();
        loudest!("   + {} {}", full_hash, name);
        branches.push(GitObject {
            full_hash,
            short_hash,
            ts_utc: commit.author().when().seconds(),
            ts_offset: (commit.author().when().offset_minutes() as i64) * 60,
            parents: vec!(),
            ref_name: Some(name.to_string()),
            author: GitAuthor {
                name: commit.author().name().map(|x| x.to_owned()),
                email: commit.author().email().map(|x| x.to_owned()),
            },
            committer: GitAuthor {
                name: commit.committer().name().map(|x| x.to_owned()),
                email: commit.committer().email().map(|x| x.to_owned()),
            },
            summary: Some(first_line(commit.message_bytes())),
            message: commit.message().map(|x| x.to_string()),
            ..Default::default()
        });
        branch_count += 1;
    }
    loud!(" - parsed {} branches", branch_count);

    loudest!(" - Parsing tags:");
    for tag in repo.tag_names(None)?.iter() {
        if tag_count >= settings.limit_tags.unwrap_or(usize::MAX) {
            break;
        }
        let tag = tag.unwrap_or("[unnamed]");
        let obj = repo.revparse_single(tag)?;
        let full_hash = obj.id().to_string();
        let short_hash = obj.short_id()?.as_str().unwrap_or_default().to_string();
        let commit = match repo.find_tag(obj.id()) {
            Ok(c) => c,
            Err(_e) => {
                error!("WARNING: tag commit not found for tag: {}", obj.id().to_string());
                tags.push(GitObject {
                    full_hash,
                    short_hash,
                    ref_name: Some(tag.to_string()),
                    ..Default::default()
                });
                tag_count += 1;
                continue;
            }
        };
        let (ts, tz) = match commit.tagger() {
            Some(t) => (t.when().seconds(), (t.when().offset_minutes() as i64) * 60),
            _ => (0, 0),
        };
        let (author,email) = match commit.tagger() {
            Some(t) => (t.name().map(|x| x.to_owned()),
                        t.email().map(|x| x.to_owned())),
            _ => (None, None),
        };
        let summary = match commit.message_bytes() {
            Some(m) => Some(first_line(m)),
            _ => None,
        };
        loudest!("   + {} {}", full_hash, tag);
        tags.push(GitObject {
            full_hash,
            short_hash,
            ts_utc: ts,
            ts_offset: tz,
            ref_name: Some(tag.to_string()),
            author: GitAuthor {
                name: author,
                email,
            },
            tagged_id: Some(commit.target_id().to_string()),
            message: commit.message().map(|x| x.to_string()),
            summary,
            ..Default::default()
        });
        tag_count += 1;
    }
    loud!(" - parsed {} tags", tag_count);

    let mut root_files: Vec<GitFile> = vec!();
    let mut all_files: Vec<GitFile> = vec!();
    let max_depth = settings.limit_tree_depth.unwrap_or(usize::MAX);
    if max_depth > 0 {
        loudest!(" - Walking root files");
        walk_file_tree(&repo, "HEAD", &mut root_files, 0, usize::MAX, false, "")?;
        // TODO: maybe this should be optional?  Walking the whole tree
        // could be slow on huge repos.
        loudest!(" - Walking all files");
        walk_file_tree(&repo, "HEAD", &mut all_files, 0, max_depth, true, "")?;
    }
    loud!(" - parsed {} files", all_files.len());

    Ok(GitRepo {
        name: name.to_string(),
        metadata,
        history,
        branches,
        tags,
        root_files,
        all_files,
        commits,
    })
}

fn parse_commit(repo: &Repository, refr: &str) -> Result<GitObject, Error> {
    let obj = repo.revparse_single(refr)?;
    let commit = repo.find_commit(obj.id())?;
    let mut parents: Vec<String> = vec!();

    let a = match commit.parents().len() {
        x if x == 1 => {
            let parent = commit.parent(0).unwrap();
            parents.push(parent.id().to_string());
            Some(parent.tree()?)
        },
        x if x > 1 => {
            for parent in commit.parents() {
                parents.push(parent.id().to_string());
            }
            None
        },
        _ => {
            None
        },
    };
    let b = commit.tree()?;
    let mut diffopts = DiffOptions::new();
    let diff = repo.diff_tree_to_tree(a.as_ref(), Some(&b), Some(&mut diffopts))?;
    let stats = diff.stats()?;

    let mut commit_diff: GitDiffCommit = GitDiffCommit {
        file_count: stats.files_changed(),
        additions: stats.insertions(),
        deletions: stats.deletions(),
        ..Default::default()
    };
    let files: Rc<RefCell<Vec<GitDiffFile>>> = Rc::new(RefCell::new(vec!()));

    diff.foreach(
        &mut |file, _progress| {
            let mut file_diff: GitDiffFile = Default::default();
            file_diff.newfile = match file.status() {
                git2::Delta::Deleted => "/dev/null".to_owned(),
                _ => file.new_file().path().map(|x| "b/".to_string() + &x.to_string_lossy()).unwrap_or("/dev/null".to_string()),
            };
            file_diff.oldfile = match file.status() {
                git2::Delta::Added => "/dev/null".to_owned(),
                _ => file.old_file().path().map(|x| "a/".to_string() + &x.to_string_lossy()).unwrap_or("/dev/null".to_string()),
            };
            file_diff.basefile = match file.status() {
                git2::Delta::Added => file.new_file().path().map(|x| x.to_string_lossy().to_string()).unwrap_or("/dev/null".to_string()),
                _ => file.old_file().path().map(|x| x.to_string_lossy().to_string()).unwrap_or("/dev/null".to_string()),
            };
            file_diff.oldid = file.old_file().id().to_string();
            file_diff.newid = file.new_file().id().to_string();
            files.borrow_mut().push(file_diff);
            true
        },
        None, // TODO: handle binary files?
        Some(&mut |_file, hunk| {
            let mut files = files.borrow_mut();
            let file_diff: &mut GitDiffFile = files.last_mut().expect("Diff hunk not associated with a file!");
            let mut hunk_diff: GitDiffHunk = Default::default();
            hunk_diff.context = String::from_utf8_lossy(hunk.header()).to_string();
            file_diff.hunks.push(hunk_diff);
            true
        }),
        Some(&mut |_file, _hunk, line| {
            let mut files = files.borrow_mut();
            let file_diff: &mut GitDiffFile = files.last_mut().expect("Diff hunk not associated with a file!");
            let hunk_diff: &mut GitDiffHunk = file_diff.hunks.last_mut().expect("Diff line not associated with a hunk!");
            let (kind, prefix) = match line.origin() {
                ' ' => ("ctx", " "),
                '-' => ("del", "-"),
                '+' => ("add", "+"),
                _ => ("other", " "),
            };
            match line.origin() {
                '-' => file_diff.deletions += 1,
                '+' => file_diff.additions += 1,
                _ => {},
            }
            let line_diff = GitDiffLine {
                text: String::from_utf8_lossy(line.content()).to_string(),
                kind,
                prefix,
            };
            hunk_diff.lines.push(line_diff);
            true
        })
    )?;

    match Rc::try_unwrap(files) {
        Ok(files) => {
            let files: Vec<GitDiffFile> = files.into_inner();
            commit_diff.files = files;
        },
        Err(_) => {},
    }

    let tree = obj.peel_to_tree()?;
    let summary = GitObject {
        full_hash: obj.id().to_string(),
        short_hash: obj.short_id()?.as_str().unwrap_or_default().to_string(),
        ts_utc: commit.author().when().seconds(),
        ts_offset: (commit.author().when().offset_minutes() as i64) * 60,
        tagged_id: None,
        tree_id: Some(tree.id().to_string()),
        parents,
        ref_name: None,
        alt_refs: vec!(),
        author: GitAuthor {
            name: commit.author().name().map(|x| x.to_string()),
            email: commit.author().email().map(|x| x.to_string()),
        },
        committer: GitAuthor {
            name: commit.committer().name().map(|x| x.to_string()),
            email: commit.committer().email().map(|x| x.to_string()),
        },
        summary: Some(first_line(commit.message_bytes())),
        message: commit.message().map(|x| x.to_string()),
        stats: None,
        diff: Some(commit_diff),
    };

    Ok(summary)
}

#[cfg(feature = "markdown")]
fn parse_markdown(contents: &str) -> String {
    let mut options = Options::empty();
    options.insert(Options::ENABLE_STRIKETHROUGH);
    options.insert(Options::ENABLE_TABLES);
    let parser = MdParser::new_ext(contents, options);
    let mut html_output: String = String::with_capacity(contents.len() * 3 / 2);
    html::push_html(&mut html_output, parser);
    html_output
}

#[cfg(any(feature = "highlight", feature = "highlight_fast"))]
fn syntax_highlight(contents: &str, extension: &str) -> String {
    let syntax_set = SyntaxSet::load_defaults_newlines();
    let syntax = match syntax_set.find_syntax_by_extension(extension) {
        Some(s) => s,
        _ => { return contents.to_string(); },
    };
    let mut html_generator = ClassedHTMLGenerator::new_with_class_style(syntax, &syntax_set, ClassStyle::Spaced);
    for line in LinesWithEndings::from(contents) {
        match html_generator.parse_html_for_line_which_includes_newline(line) {
            Ok(_) => {},
            Err(_) => {
                error!("Warning: failed to apply syntax highlighting.");
                return contents.to_string();
            },
        }
    }
    html_generator.finalize()
}

fn fill_file_contents(repo: &Repository, file: &GitFile, settings: &GitsySettingsRepo) -> Result<GitFile, Error> {
    let mut file = file.clone();
    if file.kind == "file" {
        let blob = repo.find_blob(git2::Oid::from_str(&file.id)?)?;
        file.contents = match blob.is_binary() {
            false => {
                let path = Path::new(&file.path);
                let cstr = String::from_utf8_lossy(blob.content()).to_string();
                let (content, rendered, pre) = match path.extension() {
                    #[cfg(feature = "markdown")]
                    Some(x) if settings.render_markdown.unwrap_or(false) && x == "md" => {
                        loudest!(" - rendering Markdown in {}", path.display());
                        let (cstr, rendered, pre) = (parse_markdown(&cstr), true, false);
                        (cstr, rendered, pre)
                    },
                    #[cfg(any(feature = "highlight", feature = "highlight_fast"))]
                    Some(x) if settings.syntax_highlight.unwrap_or(false) => {
                        loudest!(" - syntax highlighting {}", path.display());
                        (syntax_highlight(&cstr, x.to_string_lossy().to_string().as_str()), true, true)
                    },
                    _ => (cstr, false, true),
                };
                file.contents_safe = rendered;
                file.contents_preformatted = pre;
                Some(content)
            },
            true => Some(format!("[Binary data ({} bytes)]", blob.content().len())),
        };
    }
    Ok(file)
}

fn dir_listing(repo: &Repository, file: &GitFile) -> Result<Vec<GitFile>, Error> {
    let mut files: Vec<GitFile> = vec!();
    walk_file_tree(&repo, &file.id, &mut files, 0, usize::MAX, false, "")?;
    Ok(files)
}

struct FileFilter;
impl Filter for FileFilter {
    fn filter(&self, value: &Value, _args: &HashMap<String, Value>
    ) -> Result<Value, tera::Error> {
        let file_list: Vec<GitFile> = try_get_value!("only_files", "value", Vec<GitFile>, value);
        let file_list: Vec<GitFile> = file_list.iter().filter_map(|x| match x.kind.as_str() {
            "file" => Some(x.clone()),
            _ => None,
        }).collect();
        Ok(to_value(file_list).unwrap())
    }
}

struct DirFilter;
impl Filter for DirFilter {
    fn filter(&self, value: &Value, _args: &HashMap<String, Value>
    ) -> Result<Value, tera::Error> {
        let file_list: Vec<GitFile> = try_get_value!("only_dirs", "value", Vec<GitFile>, value);
        let file_list: Vec<GitFile> = file_list.iter().filter_map(|x| match x.kind.as_str() {
            "dir" => Some(x.clone()),
            _ => None,
        }).collect();
        Ok(to_value(file_list).unwrap())
    }
}

struct TsDateFn;
impl Function for TsDateFn {
    fn call(&self, args: &HashMap<String, Value>) -> Result<Value, tera::Error> {
        let ts: Option<i64> = match args.get("ts") {
            Some(ts) => match tera::from_value(ts.clone()) {
                Ok(ts) => Some(ts),
                _ => None,
            },
            _ => None,
        };
        let ts = ts.expect("ts_to_date missing a `ts` argument");

        let tz: Option<i64> = match args.get("tz") {
            Some(tz) => match tera::from_value(tz.clone()) {
                Ok(tz) => Some(tz),
                _ => None,
            },
            _ => None,
        };

        let fmt: Option<String> = match args.get("fmt") {
            Some(fmt) => match tera::from_value(fmt.clone()) {
                Ok(fmt) => Some(fmt),
                _ => None,
            },
            _ => None,
        };
        Ok(to_value(ts_to_date(ts, tz, fmt)).unwrap())
    }
}

struct TsTimestampFn;
impl Function for TsTimestampFn {
    fn call(&self, args: &HashMap<String, Value>) -> Result<Value, tera::Error> {
        let ts: Option<i64> = match args.get("ts") {
            Some(ts) => match tera::from_value(ts.clone()) {
                Ok(ts) => Some(ts),
                _ => None,
            },
            _ => None,
        };
        let ts = ts.expect("ts_to_git_timestamp missing a `ts` argument");

        let tz: Option<i64> = match args.get("tz") {
            Some(tz) => match tera::from_value(tz.clone()) {
                Ok(tz) => Some(tz),
                _ => None,
            },
            _ => None,
        };
        Ok(to_value(ts_to_git_timestamp(ts, tz)).unwrap())
    }
}

#[derive(Parser, Debug)]
#[command(author = "Trevor Bentley", version, about, long_about = None)]
#[command(help_template = "\
{name} v{version}, by {author-with-newline}
{about-with-newline}
{usage-heading} {usage}

{all-args}{after-help}
")]
struct CliArgs {
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,
    #[arg(short, long)]
    quiet: bool,
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
struct GitsySettings {
    recursive_repo_dirs: Option<Vec<PathBuf>>,
    site_name: Option<String>,
    site_url: Option<String>,
    site_description: Option<String>,
    asset_files: Option<Vec<String>>,
    #[serde(rename(deserialize = "gitsy_templates"))]
    templates: GitsySettingsTemplates,
    #[serde(rename(deserialize = "gitsy_outputs"))]
    outputs: GitsySettingsOutputs,
    limit_history: Option<usize>,
    limit_commits: Option<usize>,
    limit_branches: Option<usize>,
    limit_tags: Option<usize>,
    limit_tree_depth: Option<usize>,
    limit_file_size: Option<usize>,
    limit_repo_size: Option<usize>,
    limit_total_size: Option<usize>,
    render_markdown: Option<bool>,
    syntax_highlight: Option<bool>,
    syntax_highlight_theme: Option<String>,
    #[serde(rename(deserialize = "gitsy_extra"))]
    extra: Option<BTreeMap<String, toml::Value>>,
}

#[derive(Deserialize, Debug)]
struct GitsySettingsTemplates {
    path: PathBuf,
    repo_list: Option<String>,
    repo_summary: Option<String>,
    commit: Option<String>,
    branch: Option<String>,
    tag: Option<String>,
    file: Option<String>,
    dir: Option<String>,
    error: Option<String>,
}

#[derive(Deserialize, Debug)]
struct GitsySettingsOutputs {
    path: PathBuf,
    cloned_repos: Option<String>,
    repo_list: Option<String>,
    repo_summary: Option<String>,
    commit: Option<String>,
    branch: Option<String>,
    tag: Option<String>,
    file: Option<String>,
    dir: Option<String>,
    error: Option<String>,
    syntax_css: Option<String>,
    global_assets: Option<String>,
    repo_assets: Option<String>,
}

macro_rules! output_path_fn {
    ($var:ident, $obj:ty, $id:ident, $is_dir:expr, $default:expr) => {
        pub fn $var(&self, repo: Option<&GitRepo>, obj: Option<&$obj>) -> String {
            let tmpl_str = self.$var.as_deref().unwrap_or($default).to_string();
            let tmpl_str = match (tmpl_str.contains("%REPO%"), repo.is_some()) {
                (true, true) => {
                    let name = repo.map(|x| &x.name).unwrap();
                    tmpl_str.replace("%REPO%", name)
                },
                (true, false) => {
                    panic!("%REPO% variable not available for output path: {}", tmpl_str);
                }
                _ => tmpl_str,
            };
            let tmpl_str = match (tmpl_str.contains("%ID%"), obj.is_some()) {
                (true, true) => {
                    let name = obj.map(|x| &x.$id).unwrap();
                    tmpl_str.replace("%ID%", name)
                },
                (true, false) => {
                    panic!("%ID% variable not available for output path: {}", tmpl_str);
                }
                _ => tmpl_str,
            };
            let tmpl = PathBuf::from(tmpl_str);
            let mut path = self.path.clone();
            path.push(tmpl);
            match $is_dir {
                true => {
                    let _ = create_dir_all(&path);
                },
                false => {
                    if let Some(dir) = path.parent() {
                        let _ = create_dir_all(dir);
                    }
                },
            }
            path.to_str()
                .expect(&format!("Output is not a valid path: {}", path.display()))
                .into()
        }
    };
}
//step_map_first!(boil_in_wort, Boil, Wort, |b: &Boil| { b.wort_start() });

impl GitsySettingsOutputs {
    output_path_fn!(repo_list,     GitObject, full_hash, false, "repos.html");
    output_path_fn!(repo_summary,  GitObject, full_hash, false, "%REPO%/summary.html");
    output_path_fn!(commit,        GitObject, full_hash, false, "%REPO%/commit/%ID%.html");
    output_path_fn!(branch,        GitObject, full_hash, false, "%REPO%/branch/%ID%.html");
    output_path_fn!(tag,           GitObject, full_hash, false, "%REPO%/tag/%ID%.html");
    output_path_fn!(file,          GitFile,   id,        false, "%REPO%/file/%ID%.html");
    output_path_fn!(syntax_css,    GitObject, full_hash, false, "%REPO%/file/syntax.css");
    output_path_fn!(dir,           GitFile,   id,        false, "%REPO%/dir/%ID%.html");
    output_path_fn!(error,         GitObject, full_hash, false, "404.html");
    output_path_fn!(global_assets, GitObject, full_hash, true,  "assets/");
    output_path_fn!(repo_assets  , GitObject, full_hash, true,  "%REPO%/assets/");
}

#[derive(Deserialize, Default, Debug)]
struct GitsySettingsRepo {
    path: PathBuf,
    name: Option<String>,
    description: Option<String>,
    website: Option<String>,
    asset_files: Option<Vec<String>>,
    render_markdown: Option<bool>,
    syntax_highlight: Option<bool>,
    syntax_highlight_theme: Option<String>,
    attributes: Option<BTreeMap<String, toml::Value>>,
    limit_history: Option<usize>,
    limit_commits: Option<usize>,
    limit_branches: Option<usize>,
    limit_tags: Option<usize>,
    limit_tree_depth: Option<usize>,
    limit_file_size: Option<usize>,
    limit_repo_size: Option<usize>,
    limit_total_size: Option<usize>,
}

impl Hash for GitsySettingsRepo {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.path.hash(state);
    }
}
impl PartialEq for GitsySettingsRepo {
    fn eq(&self, other: &Self) -> bool {
        self.path == other.path
    }
}
impl Eq for GitsySettingsRepo {}

fn write_rendered(path: &str, rendered: &str) -> usize {
    let mut file = File::create(path)
        .expect(&format!("Unable to write to output path: {}", path));
    file.write(rendered.as_bytes())
        .expect(&format!("Failed to save rendered html to path: {}", path));
    louder!(" - wrote file: {}", path);
    rendered.as_bytes().len()
}

fn main() {
    let start_all = Instant::now();
    let cli = CliArgs::parse();
    let config_path = cli.config.as_deref().unwrap_or(Path::new("config.toml")).to_owned();
    let config_dir = config_path.parent().expect("Config file not in valid directory.").to_owned();
    let config_dir = match config_dir.to_str().unwrap_or_default().len() > 0 {
        true => config_dir,
        false => PathBuf::from("."),
    };
    let config_path = match config_path.canonicalize() {
        Ok(d) => d,
        _ => config_path.clone(),
    };
    let config_dir = match config_dir.canonicalize() {
        Ok(d) => d,
        _ => config_dir.clone(),
    };
    VERBOSITY.store(match cli.quiet {
        true => 0,
        false => (cli.verbose + 1).into(),
    }, Ordering::Relaxed);

    // Parse the known settings directly into their struct
    let toml = read_to_string(&config_path).expect(&format!("Configuration file not found: {}", config_path.display()));
    let settings: GitsySettings = toml::from_str(&toml).expect("Configuration file is invalid.");

    // Settings are valid, so let's move into the directory with the config file
    if config_dir.to_str().unwrap_or_default().len() > 0 { // empty string means current directory
        std::env::set_current_dir(&config_dir)
            .expect(&format!("Unable to set working directory to: {}", config_dir.display()));
    }

    // Get a list of all remaining TOML "tables" in the file.
    // These are the user-supplied individual repositories.
    let reserved_keys = vec!("gitsy_templates", "gitsy_outputs", "gitsy_extra");
    let settings_raw: HashMap<String, toml::Value> = toml::from_str(&toml).expect("blah");
    let table_keys: Vec<String> = settings_raw.iter().filter_map(|x| match x.1.is_table() {
        true => match reserved_keys.contains(&x.0.as_str()) {
            false => Some(x.0.clone()),
            true => None,
        },
        false => None
    }).collect();

    // Try to convert each unknown "table" into a repo struct, and
    // save the ones that are successful.  If no repo name is
    // specified, use the TOML table name.
    let mut repo_descriptions: HashSet<GitsySettingsRepo> = HashSet::new();
    macro_rules! global_to_repo {
        ($settings:ident, $repo:ident, $field:ident) => {
            if $repo.$field.is_none() { $repo.$field = $settings.$field.clone() }
        }
    }
    for k in &table_keys {
        let v = settings_raw.get(k).unwrap();
        match toml::from_str::<GitsySettingsRepo>(&v.to_string()) {
            Ok(mut repo) => {
                if repo.name.is_none() { repo.name = Some(k.clone()); }
                global_to_repo!(settings, repo, render_markdown);
                global_to_repo!(settings, repo, syntax_highlight);
                global_to_repo!(settings, repo, syntax_highlight_theme);
                global_to_repo!(settings, repo, limit_history);
                global_to_repo!(settings, repo, limit_commits);
                global_to_repo!(settings, repo, limit_branches);
                global_to_repo!(settings, repo, limit_tags);
                global_to_repo!(settings, repo, limit_tree_depth);
                global_to_repo!(settings, repo, limit_file_size);
                global_to_repo!(settings, repo, limit_repo_size);
                global_to_repo!(settings, repo, limit_total_size);

                repo_descriptions.insert(repo);
            },
            Err(e) => {
                error!("Failed to parse repo [{}]: {:?}", k, e);
            },
        }
    }

    match &settings.recursive_repo_dirs {
        Some(dirs) => {
            for parent in dirs {
                for dir in read_dir(parent).expect("Repo directory not found.") {
                    let dir = dir.expect("Repo contains invalid entries");
                    let name: String = dir.file_name().to_string_lossy().to_string();
                    repo_descriptions.insert(GitsySettingsRepo {
                        path: dir.path().clone(),
                        name: Some(name),
                        render_markdown: settings.render_markdown.clone(),
                        syntax_highlight: settings.syntax_highlight.clone(),
                        syntax_highlight_theme: settings.syntax_highlight_theme.clone(),
                        limit_history: settings.limit_history.clone(),
                        limit_commits: settings.limit_commits.clone(),
                        limit_branches: settings.limit_branches.clone(),
                        limit_tags: settings.limit_tags.clone(),
                        limit_tree_depth: settings.limit_tree_depth.clone(),
                        limit_file_size: settings.limit_file_size.clone(),
                        limit_repo_size: settings.limit_repo_size.clone(),
                        limit_total_size: settings.limit_total_size.clone(),
                        ..Default::default()
                    });
                }
            }
        },
        _ => {},
    }

    let mut template_path = settings.templates.path.clone();
    template_path.push("**");
    template_path.push("*.html");
    let mut tera = match Tera::new(template_path.to_str().expect("No template path set!")) {
        Ok(t) => t,
        Err(e) => {
            error!("Parsing error(s): {}", e);
            std::process::exit(1);
        }
    };
    tera.register_filter("only_files", FileFilter{});
    tera.register_filter("only_dirs", DirFilter{});
    tera.register_function("ts_to_date", TsDateFn{});
    tera.register_function("ts_to_git_timestamp", TsTimestampFn{});

    macro_rules! size_check {
        ($settings:ident, $cur:ident, $total:expr) => {
            if $cur > $settings.limit_repo_size.unwrap_or(usize::MAX) {
                break;
            }
            if $total + $cur > $settings.limit_total_size.unwrap_or(usize::MAX) {
                break;
            }
        }
    }

    // Create output directory
    let _ = create_dir(settings.outputs.path.to_str().expect("Output path invalid."));

    let generated_dt = chrono::offset::Local::now();
    let mut global_bytes = 0;
    let mut total_bytes = 0;
    let mut repos: Vec<GitRepo> = vec!();

    if repo_descriptions.len() == 0 {
        panic!("No Git repositories defined!  Please check your configuration file ({})",
               config_path.display());
    }

    // Sort the repositories by name
    let mut repo_vec: Vec<GitsySettingsRepo> = repo_descriptions.drain().collect();
    repo_vec.sort_by(|x,y| x.name.as_deref().map(|n| n.cmp(&y.name.as_deref().unwrap_or_default()))
                     .unwrap_or(cmp::Ordering::Equal));
    // Find the one with the longest name, for pretty printing
    let global_name = "repo list";
    let longest_repo_name = repo_vec.iter().fold(0, |acc, x| {
        cmp::max(acc, x.name.as_deref().map(|n| n.len()).unwrap_or(0))
    }).max(global_name.len());

    loudest!("Global settings:\n{:#?}", &settings);

    // Iterate over each repository, generating outputs
    for repo_desc in &repo_vec {
        loudest!("Repo settings:\n{:#?}", &repo_desc);
        let start_repo = Instant::now();
        let mut repo_bytes = 0;
        let name = repo_desc.name.as_deref().expect("A configured repository has no name!");

        let repo_path = match &repo_desc.path {
            url if url.starts_with("https://") ||
                url.to_str().unwrap_or_default().contains("@") => {
                if settings.outputs.cloned_repos.is_none() {
                    error!("ERROR: Found remote repo [{}], but `cloned_repos` directory not configured.", name);
                    continue;
                };
                let clone_path: PathBuf = [settings.outputs.cloned_repos.as_deref().unwrap(),
                                           name].iter().collect();
                match Repository::open(&clone_path) {
                    Ok(r) => {
                        // Repo already cloned, so update all refs
                        let refs: Vec<String> = r.references()
                            .expect(&format!("Unable to enumerate references for repo [{}]", name))
                            .map(|x| x.expect(&format!("Found invalid reference in repo [{}]", name))
                                 .name()
                                 .expect(&format!("Found unnamed reference in repo: [{}]", name))
                                 .to_string()).collect();
                        r.find_remote("origin")
                            .expect(&format!("Clone of repo [{}] missing `origin` remote.", name))
                            .fetch(&refs, None, None)
                            .expect(&format!("Failed to fetch updates from remote repo [{}]", name));
                        clone_path.to_string_lossy().to_string()
                    },
                    Err(_) => {
                        let mut builder = git2::build::RepoBuilder::new();

                        // TODO: git2-rs's ssh support just doesn't seem to
                        // work.  It finds the repo, but fails to either
                        // decrypt or use the private key.
                        //
                        //if !url.starts_with("https://") {
                        //    use secrecy::ExposeSecret;
                        //    // this must be SSH, which needs credentials.
                        //    let mut callbacks = git2::RemoteCallbacks::new();
                        //    callbacks.credentials(|_url, username_from_url, _allowed_types| {
                        //        //git2::Cred::ssh_key_from_agent(username_from_url.unwrap())
                        //
                        //        let keyfile = format!("{}/.ssh/id_rsa", std::env::var("HOME").unwrap());
                        //        let passphrase = pinentry::PassphraseInput::with_default_binary().unwrap()
                        //            .with_description(&format!("Enter passphrase for SSH key {} (repo: {})",
                        //                                       keyfile, url.display()))
                        //            .with_prompt("Passphrase:")
                        //            .interact().unwrap();
                        //        git2::Cred::ssh_key(
                        //            username_from_url.unwrap(),
                        //            None,
                        //            Path::new(&keyfile),
                        //            Some(passphrase.expose_secret()),
                        //        )
                        //    });
                        //    let mut options = git2::FetchOptions::new();
                        //    options.remote_callbacks(callbacks);
                        //    builder.fetch_options(options);
                        //}
                        builder
                            .bare(true)
                            .clone(&url.to_string_lossy().to_string(), &clone_path)
                            .expect(&format!("Failed to clone remote repo [{}]", name));
                        clone_path.to_string_lossy().to_string()
                    }
                }
            }
            dir => {
                match dir.metadata() {
                    Ok(m) if m.is_dir() => {},
                    _ => {
                        error!("ERROR: local repository [{}]: directory not found: {}", name, dir.display());
                        continue;
                    },
                }
                dir.to_string_lossy().to_string()
            },
        };
        let repo = Repository::open(&repo_path).expect("Unable to find git repository.");
        let metadata = GitsyMetadata {
            full_name: repo_desc.name.clone(),
            description: repo_desc.description.clone(),
            website: repo_desc.website.clone(),
            clone: None,
            attributes: repo_desc.attributes.clone().unwrap_or_default(),
        };
        normal_noln!("[{}{}]... ", name, " ".repeat(longest_repo_name - name.len()));
        let summary = parse_repo(&repo, &name, &repo_desc, metadata).expect("Failed to analyze repo HEAD.");

        let mut local_ctx = Context::from_serialize(&summary).unwrap();
        if let Some(extra) = &settings.extra {
            local_ctx.try_insert("extra", extra).expect("Failed to add extra settings to template engine.");
        }
        if let Some(site_name) = &settings.site_name {
            local_ctx.insert("site_name", site_name);
        }
        if let Some(site_url) = &settings.site_url {
            local_ctx.insert("site_url", site_url);
        }
        if let Some(site_description) = &settings.site_description {
            local_ctx.insert("site_description", site_description);
        }
        local_ctx.insert("site_generated_ts", &generated_dt.timestamp());
        local_ctx.insert("site_generated_offset", &generated_dt.offset().local_minus_utc());

        if let Some(templ_file) = settings.templates.repo_summary.as_deref() {
            match tera.render(templ_file, &local_ctx) {
                Ok(rendered) => {
                    repo_bytes += write_rendered(&settings.outputs.repo_summary(Some(&summary), None), &rendered);
                },
                Err(x) => match x.kind {
                    _ => error!("ERROR: {:?}", x),
                },
            }
        }

        for branch in &summary.branches {
            size_check!(repo_desc, repo_bytes, total_bytes);
            local_ctx.insert("branch", branch);
            if let Some(templ_file) = settings.templates.branch.as_deref() {
                match tera.render(templ_file, &local_ctx) {
                    Ok(rendered) => {
                        repo_bytes += write_rendered(&settings.outputs.branch(Some(&summary), Some(branch)), &rendered);
                    },
                    Err(x) => match x.kind {
                        _ => error!("ERROR: {:?}", x),
                    },
                }
            }
            local_ctx.remove("branch");
        }

        for tag in &summary.tags {
            size_check!(repo_desc, repo_bytes, total_bytes);
            local_ctx.insert("tag", tag);
            if let Some(tagged_id) = tag.tagged_id.as_ref() {
                if let Some(commit) = summary.commits.get(tagged_id) {
                    local_ctx.insert("commit", &commit);
                }
            }
            if let Some(templ_file) = settings.templates.tag.as_deref() {
                match tera.render(templ_file, &local_ctx) {
                    Ok(rendered) => {
                        repo_bytes += write_rendered(&settings.outputs.tag(Some(&summary), Some(tag)), &rendered);
                    },
                    Err(x) => match x.kind {
                        _ => error!("ERROR: {:?}", x),
                    },
                }
            }
            local_ctx.remove("tag");
            local_ctx.remove("commit");
        }

        for (_id, commit) in &summary.commits {
            size_check!(repo_desc, repo_bytes, total_bytes);
            local_ctx.try_insert("commit", &commit).expect("Failed to add commit to template engine.");
            if let Some(templ_file) = settings.templates.commit.as_deref() {
                match tera.render(templ_file, &local_ctx) {
                    Ok(rendered) => {
                        repo_bytes += write_rendered(&settings.outputs.commit(Some(&summary), Some(commit)), &rendered);
                    },
                    Err(x) => match x.kind {
                        _ => error!("ERROR: {:?}", x),
                    },
                }
            }
            local_ctx.remove("commit");
        }

        // TODO: most of these generation blocks can be done in
        // parallel.  This one is particularly costly, especially with
        // markdown+highlighting, and would probably benefit from it.
        // A potential drawback is that each parallel run needs a
        // clone of the Tera context.
        #[cfg(any(feature = "highlight", feature = "highlight_fast"))]
        if settings.templates.file.is_some() {
            let ts = ThemeSet::load_defaults();
            let theme = ts.themes.get(repo_desc.syntax_highlight_theme.as_deref()
                                      .unwrap_or("base16-ocean.light")).expect("Invalid syntax highlighting theme specified.");
            let css: String = css_for_theme_with_class_style(theme, syntect::html::ClassStyle::Spaced)
                .expect("Invalid syntax highlighting theme specified.");
            repo_bytes += write_rendered(&settings.outputs.syntax_css(Some(&summary), None), css.as_str());
        }

        for file in summary.all_files.iter().filter(|x| x.kind == "file") {
            size_check!(repo_desc, repo_bytes, total_bytes);
            let file = match file.size < repo_desc.limit_file_size.unwrap_or(usize::MAX) {
                true => fill_file_contents(&repo, &file, &repo_desc).expect("Failed to parse file."),
                false => file.clone(),
            };
            local_ctx.try_insert("file", &file).expect("Failed to add file to template engine.");
            if let Some(templ_file) = settings.templates.file.as_deref() {
                match tera.render(templ_file, &local_ctx) {
                    Ok(rendered) => {
                        repo_bytes += write_rendered(&settings.outputs.file(Some(&summary), Some(&file)), &rendered);
                    },
                    Err(x) => match x.kind {
                        _ => error!("ERROR: {:?}", x),
                    },
                }
            }
            local_ctx.remove("file");
        }

        for dir in summary.all_files.iter().filter(|x| x.kind == "dir") {
            size_check!(repo_desc, repo_bytes, total_bytes);
            if dir.tree_depth >= repo_desc.limit_tree_depth.unwrap_or(usize::MAX) - 1 {
                continue;
            }
            let listing = dir_listing(&repo, &dir).expect("Failed to parse file.");
            local_ctx.try_insert("files", &listing).expect("Failed to add dir to template engine.");
            if let Some(templ_file) = settings.templates.dir.as_deref() {
                match tera.render(templ_file, &local_ctx) {
                    Ok(rendered) => {
                        repo_bytes += write_rendered(&settings.outputs.dir(Some(&summary), Some(dir)), &rendered);
                    },
                    Err(x) => match x.kind {
                        _ => error!("ERROR: {:?}", x),
                    },
                }
            }
            local_ctx.remove("files");
        }

        if repo_desc.asset_files.is_some() {
            let target_dir = settings.outputs.repo_assets(Some(&summary), None);
            for src_file in repo_desc.asset_files.as_ref().unwrap() {
                let src_file = PathBuf::from(repo_path.to_owned() + "/" + src_file);
                let mut dst_file = PathBuf::from(&target_dir);
                dst_file.push(src_file.file_name()
                              .expect(&format!("Failed to copy repo asset file: {} ({})",
                                               src_file.display(), repo_desc.name.as_deref().unwrap_or_default())));
                std::fs::copy(&src_file, &dst_file)
                    .expect(&format!("Failed to copy repo asset file: {} ({})",
                                     src_file.display(), repo_desc.name.as_deref().unwrap_or_default()));
                if let Ok(meta) = std::fs::metadata(dst_file) {
                    repo_bytes += meta.len() as usize;
                }
            }
        }

        repos.push(summary);
        normal!("{}done in {:.2}s ({} bytes)",
                match VERBOSITY.load(Ordering::Relaxed) > 1 {
                    true => " - ",
                    _ => "",
                },
                start_repo.elapsed().as_secs_f32(), repo_bytes);
        total_bytes += repo_bytes;
        size_check!(repo_desc, repo_bytes, total_bytes);
    }

    let start_global = Instant::now();
    normal_noln!("[{}{}]... ", global_name, " ".repeat(longest_repo_name - global_name.len()));
    let mut global_ctx = Context::new();
    global_ctx.try_insert("repos", &repos).expect("Failed to add repo to template engine.");
    if let Some(extra) = &settings.extra {
        global_ctx.try_insert("extra", extra).expect("Failed to add extra settings to template engine.");
    }
    if let Some(site_name) = &settings.site_name {
        global_ctx.insert("site_name", site_name);
    }
    if let Some(site_url) = &settings.site_url {
        global_ctx.insert("site_url", site_url);
    }
    if let Some(site_description) = &settings.site_description {
        global_ctx.insert("site_description", site_description);
    }
    global_ctx.insert("site_generated_ts", &generated_dt.timestamp());
    global_ctx.insert("site_generated_offset", &generated_dt.offset().local_minus_utc());

    if let Some(templ_file) = settings.templates.repo_list.as_deref() {
        match tera.render(templ_file, &global_ctx) {
            Ok(rendered) => {
                global_bytes += write_rendered(&settings.outputs.repo_list(None, None), &rendered);
            },
            Err(x) => match x.kind {
                _ => error!("ERROR: {:?}", x),
            },
        }
    }

    if let Some(templ_file) = settings.templates.error.as_deref() {
        match tera.render(templ_file, &global_ctx) {
            Ok(rendered) => {
                global_bytes += write_rendered(&settings.outputs.error(None, None), &rendered);
            },
            Err(x) => match x.kind {
                _ => error!("ERROR: {:?}", x),
            },
        }
    }

    if settings.asset_files.is_some() {
        let target_dir = settings.outputs.global_assets(None, None);
        for src_file in settings.asset_files.unwrap() {
            let src_file = PathBuf::from(src_file);
            let mut dst_file = PathBuf::from(&target_dir);
            dst_file.push(src_file.file_name()
                          .expect(&format!("Failed to copy asset file: {}", src_file.display())));
            std::fs::copy(&src_file, &dst_file)
                .expect(&format!("Failed to copy asset file: {}", src_file.display()));
            if let Ok(meta) = std::fs::metadata(dst_file) {
                global_bytes += meta.len() as usize;
            }
        }
    }

    total_bytes += global_bytes;
    normal!("done in {:.2}s ({} bytes)", start_global.elapsed().as_secs_f32(), global_bytes);
    loud!("Wrote {} bytes in {:.2}s", total_bytes, start_all.elapsed().as_secs_f32());
}

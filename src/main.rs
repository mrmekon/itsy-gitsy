use chrono::{
    DateTime,
    offset::FixedOffset,
    naive::NaiveDateTime,
};
use clap::Parser;
use git2::{DiffOptions, Repository, Error};
use serde::{Serialize, Deserialize};
use std::collections::{BTreeMap, HashMap};
use std::io::Write;
use std::path::{Path, PathBuf};
use tera::{Context, Filter, Function, Tera, Value, to_value, try_get_value};

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
    metadata: ItsyMetadata,
    history: Vec<GitObject>,
    branches: Vec<GitObject>,
    tags: Vec<GitObject>,
    root_files: Vec<GitFile>,
    all_files: Vec<GitFile>,
    commits: BTreeMap<String, GitObject>,
}

#[derive(Serialize, Default)]
struct ItsyMetadata {
    full_name: Option<String>,
    description: Option<String>,
    website: Option<String>,
    clone: Option<String>,
    attributes: BTreeMap<String, String>,
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
    contents: Option<String>,
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
                  depth: usize, recurse: bool, prefix: &str) -> Result<(), Error> {
    let obj = repo.revparse_single(rev)?;
    let tree = obj.peel_to_tree()?;
    for entry in tree.iter() {
        let name = prefix.to_string() + entry.name().unwrap_or_default();
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
        files.push(GitFile {
            id: entry.id().to_string(),
            name: name.clone(),
            path: match depth {
                0 => name.to_string(),
                _ => format!("{}/{}", prefix, name),
            },
            kind: kind.to_string(),
            mode: entry.filemode(),
            is_binary,
            size,
            contents: None,
        });
        if recurse && entry.kind() == Some(git2::ObjectType::Tree) {
            let prefix = name + "/";
            walk_file_tree(repo, &entry.id().to_string(), files, depth+1, true, &prefix)?;
        }
    }
    Ok(())
}

fn parse_repo(repo: &Repository, name: &str) -> Result<GitRepo, Error> {
    let mut history: Vec<GitObject> = vec!();
    let mut branches: Vec<GitObject> = vec!();
    let mut tags: Vec<GitObject> = vec!();
    let mut commits: BTreeMap<String, GitObject> = BTreeMap::new();

    let mut revwalk = repo.revwalk()?;
    revwalk.set_sorting(git2::Sort::TOPOLOGICAL)?;
    revwalk.push_head()?;
    for oid in revwalk {
        let oid = oid?;
        commits.insert(oid.to_string(), parse_commit(repo, &oid.to_string())?);
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

        // TODO: is it acceptable to iterate over all references for
        // every commit?  Is there another way?  Should probably cache
        // all of the ref IDs in memory.
        let mut alt_refs = vec!();
        for refr in repo.references()? {
            let refr = refr?;
            if let Some(target) = refr.target() {
                if target == commit.id() {
                    // TODO: save these
                    if let Some(name) = refr.shorthand() {
                        alt_refs.push(name.to_string());
                    }
                }
            }
        }

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
    }

    for branch in repo.branches(None)? {
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
    }
    for tag in repo.tag_names(None)?.iter() {
        let tag = tag.unwrap_or("[unnamed]");
        let obj = repo.revparse_single(tag)?;
        let commit = repo.find_tag(obj.id())?;
        let full_hash = obj.id().to_string();
        let short_hash = obj.short_id()?.as_str().unwrap_or_default().to_string();
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
    }

    let mut root_files: Vec<GitFile> = vec!();
    let mut all_files: Vec<GitFile> = vec!();
    walk_file_tree(&repo, "origin/HEAD", &mut root_files, 0, false, "")?;
    // TODO: maybe this should be optional?  Walking the whole tree
    // could be slow on huge repos.
    walk_file_tree(&repo, "origin/HEAD", &mut all_files, 0, true, "")?;

    Ok(GitRepo {
        name: name.to_string(),
        metadata: Default::default(),
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
    let files: std::rc::Rc<std::cell::RefCell<Vec<GitDiffFile>>> = std::rc::Rc::new(std::cell::RefCell::new(vec!()));

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

    match std::rc::Rc::try_unwrap(files) {
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

fn fill_file_contents(repo: &Repository, file: &GitFile) -> Result<GitFile, Error> {
    let mut file = file.clone();
    if file.kind == "file" {
        let blob = repo.find_blob(git2::Oid::from_str(&file.id)?)?;
        file.contents = match blob.is_binary() {
            false => Some(String::from_utf8_lossy(blob.content()).to_string()),
            true => Some(format!("[Binary data ({} bytes)]", blob.content().len())),
        };
    }
    Ok(file)
}

fn dir_listing(repo: &Repository, file: &GitFile) -> Result<Vec<GitFile>, Error> {
    let mut files: Vec<GitFile> = vec!();
    walk_file_tree(&repo, &file.id, &mut files, 0, false, "")?;
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
#[command(author, version, about, long_about = None)]
struct CliArgs {
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,
}

#[derive(Deserialize)]
#[allow(dead_code)]
struct ItsySettings {
    template_dir: PathBuf,
    output_dir: PathBuf,
    recursive_repo_dirs: Option<Vec<PathBuf>>,
    extra: HashMap<String, toml::Value>,
}
#[derive(Deserialize)]
#[allow(dead_code)]
struct ItsySettingsRepo {
    path: PathBuf,
    name: Option<String>,
    description: Option<String>,
    website: Option<String>,
}

fn main() {
    let cli = CliArgs::parse();
    let config_path = cli.config.as_deref().unwrap_or(Path::new("config.toml"));

    // Parse the known settings directly into their struct
    let toml = std::fs::read_to_string(config_path).expect(&format!("Configuration file not found: {}", config_path.display()));
    let settings: ItsySettings = toml::from_str(&toml).expect("Configuration file is invalid.");

    // Get a list of all remaining TOML "tables" in the file.
    // These are the user-supplied individual repositories.
    let reserved_keys = vec!("repos","extra");
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
    let mut repos: Vec<ItsySettingsRepo> = vec!();
    for k in &table_keys {
        let v = settings_raw.get(k).unwrap();
        match toml::from_str::<ItsySettingsRepo>(&v.to_string()) {
            Ok(mut repo) => {
                if repo.name.is_none() {
                    repo.name = Some(k.clone());
                }
                repos.push(repo);
            },
            _ => {},
        }
    }

    for repo in &repos {
        println!("Parse repo: {}", repo.name.as_ref().unwrap());
    }

    let mut template_path = settings.template_dir.clone();
    template_path.push("**");
    template_path.push("*.html");
    let mut tera = match Tera::new(template_path.to_str().expect("No template path set!")) {
        Ok(t) => t,
        Err(e) => {
            println!("Parsing error(s): {}", e);
            ::std::process::exit(1);
        }
    };
    tera.register_filter("only_files", FileFilter{});
    tera.register_filter("only_dirs", DirFilter{});
    tera.register_function("ts_to_date", TsDateFn{});
    tera.register_function("ts_to_git_timestamp", TsTimestampFn{});

    // Create output directory
    let _ = std::fs::create_dir(settings.output_dir.to_str().expect("Output path not set!"));

    let mut repos: Vec<GitRepo> = vec!();
    for dir in std::fs::read_dir(std::path::Path::new("repos")).expect("Repo directory not found.") {
        let dir = dir.expect("Repo contains invalid entries");
        match dir.metadata() {
            Ok(m) if m.is_dir() => {},
            _ => continue,
        }
        let path: String = dir.path().to_string_lossy().to_string();
        let name: String = dir.file_name().to_string_lossy().to_string();
        let repo = Repository::open(path).expect("Unable to find git repository.");
        let summary = parse_repo(&repo, &name).expect("Failed to analyze repo HEAD.");

        let mut local_ctx = Context::from_serialize(&summary).unwrap();
        match tera.render("summary.html", &local_ctx) {
            Ok(rendered) => {
                let mut output_path = settings.output_dir.clone();
                output_path.push(&name);
                let _ = std::fs::create_dir(output_path.to_str().expect("Output path not set!"));
                output_path.push("summary.html");
                let mut file = std::fs::File::create(output_path.to_str().expect("Output path not set!")).unwrap();
                file.write(rendered.as_bytes()).expect("failed to save rendered html");
            },
            Err(x) => println!("ERROR: {:?}", x),
        }

        for branch in &summary.branches {
            local_ctx.insert("branch", branch);
            match tera.render("branch.html", &local_ctx) {
                Ok(rendered) => {
                    let mut output_path = settings.output_dir.clone();
                    output_path.push(&summary.name);
                    output_path.push("branch");
                    let _ = std::fs::create_dir(output_path.to_str().expect("Output path not set!"));
                    output_path.push(format!("{}.html", branch.full_hash));
                    let mut file = std::fs::File::create(output_path.to_str().expect("Output path not set!")).unwrap();
                    file.write(rendered.as_bytes()).expect("failed to save rendered html");
                },
                Err(x) => match x.kind {
                    tera::ErrorKind::TemplateNotFound(_) => {},
                    _ => println!("ERROR: {:?}", x),
                },
            }
            local_ctx.remove("branch");
        }

        for tag in &summary.tags {
            local_ctx.insert("tag", tag);
            if let Some(commit) = summary.commits.get(tag.tagged_id.as_ref().unwrap()) {
                local_ctx.insert("commit", &commit);
            }
            match tera.render("tag.html", &local_ctx) {
                Ok(rendered) => {
                    let mut output_path = settings.output_dir.clone();
                    output_path.push(&summary.name);
                    output_path.push("tag");
                    let _ = std::fs::create_dir(output_path.to_str().expect("Output path not set!"));
                    output_path.push(format!("{}.html", tag.full_hash));
                    let mut file = std::fs::File::create(output_path.to_str().expect("Output path not set!")).unwrap();
                    file.write(rendered.as_bytes()).expect("failed to save rendered html");
                },
                Err(x) => match x.kind {
                    tera::ErrorKind::TemplateNotFound(_) => {},
                    _ => println!("ERROR: {:?}", x),
                },
            }
            local_ctx.remove("tag");
            local_ctx.remove("commit");
        }

        for (_id, commit) in &summary.commits {
            local_ctx.try_insert("commit", &commit).expect("Failed to add commit to template engine.");
            match tera.render("commit.html", &local_ctx) {
                Ok(rendered) => {
                    let mut output_path = settings.output_dir.clone();
                    output_path.push(&summary.name);
                    output_path.push("commit");
                    let _ = std::fs::create_dir(output_path.to_str().expect("Output path not set!"));
                    output_path.push(format!("{}.html", commit.full_hash));
                    let mut file = std::fs::File::create(output_path.to_str().expect("Output path not set!")).unwrap();
                    file.write(rendered.as_bytes()).expect("failed to save rendered html");
                },
                Err(x) => println!("ERROR: {:?}", x),
            }
            local_ctx.remove("commit");
        }

        for file in summary.all_files.iter().filter(|x| x.kind == "file") {
            let file = fill_file_contents(&repo, &file).expect("Failed to parse file.");
            local_ctx.try_insert("file", &file).expect("Failed to add file to template engine.");
            match tera.render("file.html", &local_ctx) {
                Ok(rendered) => {
                    let mut output_path = settings.output_dir.clone();
                    output_path.push(&summary.name);
                    output_path.push("file");
                    let _ = std::fs::create_dir(output_path.to_str().expect("Output path not set!"));
                    output_path.push(format!("{}.html", file.id));
                    let mut file = std::fs::File::create(output_path.to_str().expect("Output path not set!")).unwrap();
                    file.write(rendered.as_bytes()).expect("failed to save rendered html");
                },
                Err(x) => println!("ERROR: {:?}", x),
            }
            local_ctx.remove("file");
        }

        for dir in summary.all_files.iter().filter(|x| x.kind == "dir") {
            let listing = dir_listing(&repo, &dir).expect("Failed to parse file.");
            local_ctx.try_insert("files", &listing).expect("Failed to add dir to template engine.");
            match tera.render("dir.html", &local_ctx) {
                Ok(rendered) => {
                    let mut output_path = settings.output_dir.clone();
                    output_path.push(&summary.name);
                    output_path.push("dir");
                    let _ = std::fs::create_dir(output_path.to_str().expect("Output path not set!"));
                    output_path.push(format!("{}.html", dir.id));
                    let mut file = std::fs::File::create(output_path.to_str().expect("Output path not set!")).unwrap();
                    file.write(rendered.as_bytes()).expect("failed to save rendered html");
                },
                Err(x) => println!("ERROR: {:?}", x),
            }
            local_ctx.remove("files");
        }

        repos.push(summary);
    }

    let mut global_ctx = Context::new();
    global_ctx.try_insert("repos", &repos).expect("Failed to add repo to template engine.");
    match tera.render("repos.html", &global_ctx) {
        Ok(rendered) => {
            let mut output_path = settings.output_dir.clone();
            output_path.push("repos.html");
            let mut file = std::fs::File::create(output_path.to_str().expect("Output path not set!")).unwrap();
            file.write(rendered.as_bytes()).expect("failed to save rendered html");
        },
        Err(x) => println!("ERROR: {:?}", x),
    }
}

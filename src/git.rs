use crate::settings::GitsySettingsRepo;
use crate::{error, loud, loudest};
use git2::{DiffOptions, Error, Repository};
use serde::{Deserialize, Serialize};
use std::cell::RefCell;
use std::collections::BTreeMap;
use std::rc::Rc;
use std::sync::atomic::Ordering;

fn first_line(msg: &[u8]) -> String {
    let message = String::from_utf8_lossy(msg);
    message.lines().next().unwrap_or("[no commit message]").to_owned()
}

#[derive(Serialize, Default)]
pub struct GitRepo {
    pub name: String,
    pub metadata: GitsyMetadata,
    pub history: Vec<GitObject>,
    pub branches: Vec<GitObject>,
    pub tags: Vec<GitObject>,
    pub root_files: Vec<GitFile>,
    pub all_files: Vec<GitFile>,
    pub commits: BTreeMap<String, GitObject>,
    // TODO: this is duplication that should be handled with
    // references.  Used so templates can deduce which files have been
    // generated.
    pub commit_ids: Vec<String>,
    pub file_ids: Vec<String>,
}

impl GitRepo {
    pub fn minimal_clone(&self, max_entries: usize) -> Self {
        let mut new_commits: BTreeMap<String, GitObject> = BTreeMap::new();
        let new_history: Vec<GitObject> = self.history.iter().cloned().take(max_entries).collect();
        for entry in &new_history {
            if self.commits.contains_key(&entry.full_hash) {
                new_commits.insert(entry.full_hash.clone(),
                                   self.commits.get(&entry.full_hash).unwrap().clone());
            }
        }
        let all_files: Vec<GitFile> = self.all_files.iter().cloned().take(max_entries).collect();
        GitRepo {
            name: self.name.clone(),
            metadata: self.metadata.clone(),
            history: new_history,
            branches: self.branches.iter().cloned().take(max_entries).collect(),
            tags: self.tags.iter().cloned().take(max_entries).collect(),
            // Don't minimize the root tree, because that's weird UX
            // for the summary page.
            root_files: self.root_files.clone(),
            all_files,
            commits: new_commits,
            // These are not minimized because they're a listing of
            // which generated files should exist, and are needed for
            // ensuring valid links on every page.
            file_ids: self.file_ids.clone(),
            commit_ids: self.commit_ids.clone(),
        }
    }
}

#[derive(Clone, Serialize, Default)]
pub struct GitsyMetadata {
    pub full_name: Option<String>,
    pub description: Option<String>,
    pub website: Option<String>,
    pub clone: Option<String>,
    pub attributes: BTreeMap<String, toml::Value>,
}

#[derive(Clone, Serialize, Default)]
pub struct GitAuthor {
    pub name: Option<String>,
    pub email: Option<String>,
}

#[derive(Clone, Serialize, Default)]
pub struct GitObject {
    pub full_hash: String,
    pub short_hash: String,
    pub ts_utc: i64,
    pub ts_offset: i64,
    pub author: GitAuthor,
    pub committer: GitAuthor,
    pub parents: Vec<String>,
    pub ref_name: Option<String>,
    pub alt_refs: Vec<String>,
    pub tagged_id: Option<String>,
    pub tree_id: Option<String>,
    pub summary: Option<String>,
    pub message: Option<String>,
    pub stats: Option<GitStats>,
    pub diff: Option<GitDiffCommit>,
}

#[derive(Clone, Serialize, Default)]
pub struct GitStats {
    pub files: usize,
    pub additions: usize,
    pub deletions: usize,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct GitFile {
    pub id: String,
    pub name: String,
    pub path: String,
    pub mode: i32,
    pub kind: String,
    pub is_binary: bool,
    pub size: usize,
    pub tree_depth: usize,
    pub contents: Option<String>,
    pub contents_safe: bool,
    pub contents_preformatted: bool,
}

#[derive(Clone, Serialize, Default)]
pub struct GitDiffCommit {
    pub files: Vec<GitDiffFile>,
    pub file_count: usize,
    pub additions: usize,
    pub deletions: usize,
}

#[derive(Clone, Serialize, Default)]
pub struct GitDiffFile {
    pub oldfile: String,
    pub newfile: String,
    pub basefile: String,
    pub oldid: String,
    pub newid: String,
    pub extra: String,
    pub additions: usize,
    pub deletions: usize,
    pub hunks: Vec<GitDiffHunk>,
}

#[derive(Clone, Serialize, Default)]
pub struct GitDiffHunk {
    pub context: String,
    pub lines: Vec<GitDiffLine>,
}

#[derive(Clone, Serialize)]
pub struct GitDiffLine {
    pub kind: &'static str,
    pub prefix: &'static str,
    pub text: String,
}

fn walk_file_tree(
    repo: &git2::Repository,
    rev: &str,
    files: &mut Vec<GitFile>,
    depth: usize,
    max_depth: usize,
    recurse: bool,
    prefix: &str,
) -> Result<(), Error> {
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
            walk_file_tree(
                repo,
                &entry.id().to_string(),
                files,
                depth + 1,
                max_depth,
                true,
                &prefix,
            )?;
        }
    }
    Ok(())
}

pub fn dir_listing(repo: &Repository, file: &GitFile) -> Result<Vec<GitFile>, Error> {
    let mut files: Vec<GitFile> = vec![];
    walk_file_tree(&repo, &file.id, &mut files, 0, usize::MAX, false, "")?;
    Ok(files)
}

pub fn parse_repo(
    repo: &Repository,
    name: &str,
    settings: &GitsySettingsRepo,
    metadata: GitsyMetadata,
) -> Result<GitRepo, Error> {
    let mut history: Vec<GitObject> = vec![];
    let mut branches: Vec<GitObject> = vec![];
    let mut tags: Vec<GitObject> = vec![];
    let mut commits: BTreeMap<String, GitObject> = BTreeMap::new();
    let mut commit_count = 0;
    let mut history_count = 0;
    let mut branch_count = 0;
    let mut tag_count = 0;
    let branch_name = settings.branch.as_deref().unwrap_or("master");
    let branch_obj = repo.revparse_single(branch_name)?;

    loud!();

    // Cache the shortnames of all references
    loudest!(" - Parsing references");
    let mut references: BTreeMap<String, Vec<String>> = BTreeMap::new();
    for refr in repo.references()? {
        let refr = refr?;
        if let (Some(target), Some(name)) = (refr.target(), refr.shorthand()) {
            let id = target.to_string();
            match references.contains_key(&id) {
                false => {
                    references.insert(target.to_string(), vec![name.to_string()]);
                }
                true => {
                    references.get_mut(&id).unwrap().push(name.to_string());
                }
            }
        }
    }
    loud!(" - parsed {} references", references.len());

    let mut revwalk = repo.revwalk()?;
    // TODO: TOPOLOGICAL might be better, but it's also ungodly slow
    // on large repos.  Maybe this should be configurable.
    //
    //revwalk.set_sorting(git2::Sort::TOPOLOGICAL)?;
    revwalk.set_sorting(git2::Sort::NONE)?;
    revwalk.push(branch_obj.id())?;
    loudest!(" - Parsing history:");
    for (idx, oid) in revwalk.by_ref().enumerate() {
        let oid = oid?;
        if commit_count >= settings.limit_commits.unwrap_or(usize::MAX)
            || history_count >= settings.limit_history.unwrap_or(usize::MAX)
        {
            break;
        }
        commits.insert(oid.to_string(), parse_commit(idx, settings, repo, &oid.to_string())?);
        commit_count += 1;
        let commit = repo.find_commit(oid)?;
        let obj = repo.revparse_single(&commit.id().to_string())?;
        let full_hash = commit.id().to_string();
        let short_hash = obj.short_id()?.as_str().unwrap_or_default().to_string();

        let mut parents: Vec<String> = vec![];
        let a = match commit.parents().len() {
            x if x == 1 => {
                let parent = commit.parent(0).unwrap();
                parents.push(parent.id().to_string());
                Some(parent.tree()?)
            }
            x if x > 1 => {
                for parent in commit.parents() {
                    parents.push(parent.id().to_string());
                }
                let parent = commit.parent(0).unwrap();
                Some(parent.tree()?)
            }
            _ => None,
        };
        let b = commit.tree()?;
        let mut diffopts = DiffOptions::new();
        let stats = match idx < settings.limit_diffs.unwrap_or(usize::MAX) {
            true => {
                let diff = repo.diff_tree_to_tree(a.as_ref(), Some(&b), Some(&mut diffopts))?;
                let stats = diff.stats()?;
                let stats = GitStats {
                    files: stats.files_changed(),
                    additions: stats.insertions(),
                    deletions: stats.deletions(),
                };
                Some(stats)
            },
            false => {
                None
            },
        };

        let alt_refs: Vec<String> = references
            .get(&commit.id().to_string())
            .map(|x| x.to_owned())
            .unwrap_or_default();

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
                    name: commit.author().name().map(|x| x.to_owned()),
                    email: commit.author().email().map(|x| x.to_owned()),
                },
                summary: Some(first_line(commit.message_bytes())),
                stats,
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
            _ => {}
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
            parents: vec![],
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
    for tag in repo.tag_names(None)?.iter().rev() {
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
        let (author, email) = match commit.tagger() {
            Some(t) => (t.name().map(|x| x.to_owned()), t.email().map(|x| x.to_owned())),
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
            author: GitAuthor { name: author, email },
            tagged_id: Some(commit.target_id().to_string()),
            message: commit.message().map(|x| x.to_string()),
            summary,
            ..Default::default()
        });
        tag_count += 1;
    }
    loud!(" - parsed {} tags", tag_count);

    let mut root_files: Vec<GitFile> = vec![];
    let mut all_files: Vec<GitFile> = vec![];
    let max_depth = settings.limit_tree_depth.unwrap_or(usize::MAX);
    if max_depth > 0 {
        loudest!(" - Walking root files");
        walk_file_tree(&repo, branch_name, &mut root_files, 0, usize::MAX, false, "")?;
        // TODO: maybe this should be optional?  Walking the whole tree
        // could be slow on huge repos.
        loudest!(" - Walking all files");
        walk_file_tree(&repo, branch_name, &mut all_files, 0, max_depth, true, "")?;
    }
    loud!(" - parsed {} files", all_files.len());

    let file_ids = all_files.iter().map(|x| x.id.clone()).collect();
    let commit_ids = commits.keys().cloned().collect();
    Ok(GitRepo {
        name: name.to_string(),
        metadata,
        history,
        branches,
        tags,
        root_files,
        all_files,
        commits,
        commit_ids,
        file_ids,
    })
}

pub fn parse_commit(idx: usize, settings: &GitsySettingsRepo,
                    repo: &Repository, refr: &str) -> Result<GitObject, Error> {
    let obj = repo.revparse_single(refr)?;
    let commit = repo.find_commit(obj.id())?;
    let mut parents: Vec<String> = vec![];

    let a = match commit.parents().len() {
        x if x == 1 => {
            let parent = commit.parent(0).unwrap();
            parents.push(parent.id().to_string());
            Some(parent.tree()?)
        }
        x if x > 1 => {
            for parent in commit.parents() {
                parents.push(parent.id().to_string());
            }
            let parent = commit.parent(0).unwrap();
            Some(parent.tree()?)
        }
        _ => None,
    };
    let b = commit.tree()?;
    let mut diffopts = DiffOptions::new();
    diffopts.enable_fast_untracked_dirs(true);
    let diff = repo.diff_tree_to_tree(a.as_ref(), Some(&b), Some(&mut diffopts))?;
    let commit_diff: Option<GitDiffCommit> = match idx < settings.limit_diffs.unwrap_or(usize::MAX) {
        true => {
            let stats = diff.stats()?;

            Some(GitDiffCommit {
                file_count: stats.files_changed(),
                additions: stats.insertions(),
                deletions: stats.deletions(),
                ..Default::default()
            })
        },
        false => {
            None
        }
    };

    let commit_diff = match commit_diff {
        None => None,
        Some(mut commit_diff) => {
            let files: Rc<RefCell<Vec<GitDiffFile>>> = Rc::new(RefCell::new(vec![]));
            diff.foreach(
                &mut |file, _progress| {
                    let mut file_diff: GitDiffFile = Default::default();
                    file_diff.newfile = match file.status() {
                        git2::Delta::Deleted => "/dev/null".to_owned(),
                        _ => file
                            .new_file()
                            .path()
                            .map(|x| "b/".to_string() + &x.to_string_lossy())
                            .unwrap_or("/dev/null".to_string()),
                    };
                    file_diff.oldfile = match file.status() {
                        git2::Delta::Added => "/dev/null".to_owned(),
                        _ => file
                            .old_file()
                            .path()
                            .map(|x| "a/".to_string() + &x.to_string_lossy())
                            .unwrap_or("/dev/null".to_string()),
                    };
                    file_diff.basefile = match file.status() {
                        git2::Delta::Added => file
                            .new_file()
                            .path()
                            .map(|x| x.to_string_lossy().to_string())
                            .unwrap_or("/dev/null".to_string()),
                        _ => file
                            .old_file()
                            .path()
                            .map(|x| x.to_string_lossy().to_string())
                            .unwrap_or("/dev/null".to_string()),
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
                    let hunk_diff: &mut GitDiffHunk = file_diff
                        .hunks
                        .last_mut()
                        .expect("Diff line not associated with a hunk!");
                    let (kind, prefix) = match line.origin() {
                        ' ' => ("ctx", " "),
                        '-' => ("del", "-"),
                        '+' => ("add", "+"),
                        _ => ("other", " "),
                    };
                    match line.origin() {
                        '-' => file_diff.deletions += 1,
                        '+' => file_diff.additions += 1,
                        _ => {}
                    }
                    let line_diff = GitDiffLine {
                        text: String::from_utf8_lossy(line.content()).to_string(),
                        kind,
                        prefix,
                    };
                    hunk_diff.lines.push(line_diff);
                    true
                }),
            )?;

            match Rc::try_unwrap(files) {
                Ok(files) => {
                    let files: Vec<GitDiffFile> = files.into_inner();
                    commit_diff.files = files;
                }
                Err(_) => {}
            }
            Some(commit_diff)
        }
    };

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
        alt_refs: vec![],
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
        diff: commit_diff,
    };

    Ok(summary)
}

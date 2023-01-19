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
use crate::git::GitRepo;
use crate::util::SafePathVar;
use crate::{error, louder};
use clap::Parser;
use git2::Repository;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{create_dir, create_dir_all, read_dir, read_to_string, remove_dir_all};
use std::hash::{Hash, Hasher};
use std::path::{Path, PathBuf};
use std::sync::atomic::Ordering;

#[derive(Parser, Debug)]
#[command(author = "Trevor Bentley", version, about, long_about = None)]
#[command(help_template = "\
{name} v{version}, by {author-with-newline}
{about-with-newline}
{usage-heading} {usage}

{all-args}{after-help}
")]
struct CliArgs {
    /// Path to TOML configuration file
    #[arg(short, long, value_name = "FILE")]
    config: Option<PathBuf>,
    /// Specify path to a repository.  Overrides config TOML.  Can use multiple times.
    #[arg(short, long)]
    repo: Vec<PathBuf>,
    /// Generate a site suitable for local browsing (file://)
    #[arg(short, long)]
    local: bool,
    /// Open browser to repository listing after generation.
    #[arg(long)]
    open: bool,
    /// Remove output directory before generating.
    #[arg(long)]
    clean: bool,
    /// Don't show any output, except errors and warnings
    #[arg(short, long)]
    quiet: bool,
    /// Increase verbosity of output.  Specify up to 4 times.
    #[arg(short, long, action = clap::ArgAction::Count)]
    verbose: u8,
}

pub struct GitsyCli {
    pub path: PathBuf,
    pub dir: PathBuf,
    pub is_local: bool,
    pub should_open: bool,
    pub should_clean: bool,
    pub repos: Vec<PathBuf>,
}

impl GitsyCli {
    pub fn new() -> Self {
        let cli = CliArgs::parse();
        let config_path = cli.config.as_deref().unwrap_or(Path::new("config.toml")).to_owned();
        let config_dir = config_path
            .parent()
            .expect("Config file not in valid directory.")
            .to_owned();
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
        crate::util::VERBOSITY.store(
            match cli.quiet {
                true => 0,
                false => (cli.verbose + 1).into(),
            },
            Ordering::Relaxed,
        );
        GitsyCli {
            path: config_path,
            dir: config_dir,
            is_local: cli.local,
            should_open: cli.open,
            should_clean: cli.clean,
            repos: cli.repo,
        }
    }
}

#[derive(Deserialize, Debug)]
pub struct GitsySettingsOutputs {
    pub output_root: PathBuf,
    pub template_root: PathBuf,
    pub templates: Option<Vec<GitsySettingsTemplate>>,
    pub cloned_repos: Option<String>,
    pub syntax_css: Option<String>,
    pub global_assets: Option<String>,
    pub repo_assets: Option<String>,
}

#[derive(Deserialize, Debug, PartialEq)]
#[allow(non_camel_case_types)]
pub enum GitsyTemplateType {
    repo_list,
    summary,
    history,
    commit,
    branches,
    branch,
    tags,
    tag,
    files,
    file,
    dir,
    error,
}

pub fn substitute_path_vars<P, S>(path: &P, repo: Option<&GitRepo>, obj: Option<&S>) -> PathBuf
where
    P: AsRef<Path>,
    S: SafePathVar,
{
    let p: PathBuf = path.as_ref().to_path_buf();
    assert!(
        p.is_relative(),
        "ERROR: path must be relative, not absolute: {}",
        p.display()
    );
    let p: PathBuf = repo.map(|r| r.safe_substitute(&p)).unwrap_or(p);
    let p: PathBuf = obj.map(|o| o.safe_substitute(&p)).unwrap_or(p);
    p
}

#[derive(Deserialize, Debug)]
pub struct GitsySettingsTemplate {
    pub template: String,
    pub output: String,
    pub kind: GitsyTemplateType,
}

macro_rules! template_fn {
    ($var:ident, $is_dir:expr, $default:expr) => {
        pub fn $var<S: SafePathVar>(&self, repo: Option<&GitRepo>, obj: Option<&S>) -> PathBuf {
            let tmpl_path = PathBuf::from(self.$var.as_deref().unwrap_or($default));
            let new_path = substitute_path_vars(&tmpl_path, repo, obj);
            self.canonicalize_and_create(&new_path, $is_dir)
        }
    };
}

macro_rules! templates_fn {
    ($var:ident, $is_dir:expr) => {
        pub fn $var<S: SafePathVar>(&self, repo: Option<&GitRepo>, obj: Option<&S>) -> Vec<(PathBuf, PathBuf)> {
            match &self.templates {
                Some(template) => template
                    .iter()
                    .filter(|x| x.kind == GitsyTemplateType::$var)
                    .map(|x| {
                        let tmpl_path = PathBuf::from(&x.output);
                        let new_path = substitute_path_vars(&tmpl_path, repo, obj);
                        (
                            PathBuf::from(&x.template),
                            self.canonicalize_and_create(&new_path, $is_dir),
                        )
                    })
                    .collect(),
                None => {
                    vec![]
                }
            }
        }
    };
}

impl SafePathVar for GitsySettingsOutputs {
    fn safe_substitute(&self, path: &impl AsRef<Path>) -> PathBuf {
        let src: &Path = path.as_ref();
        let mut dst = PathBuf::new();
        let root = self.template_root.to_str().expect(&format!(
            "ERROR: couldn't parse template root: {}",
            self.template_root.display()
        ));
        for cmp in src.components() {
            // NOTE: this variable is not sanitized, since it's
            // allowed to create new directory structure.
            let cmp = cmp.as_os_str().to_string_lossy().replace("%TEMPLATE%", &root);
            dst.push(cmp);
        }
        dst
    }
}

#[rustfmt::skip]
impl GitsySettingsOutputs {
    // Single entries:
    template_fn!(syntax_css,    false, "%REPO%/file/syntax.css");
    template_fn!(global_assets, true,  "assets/");
    template_fn!(repo_assets,   true,  "%REPO%/assets/");
    // Zero or more entries (Vec):
    templates_fn!(repo_list, false);
    templates_fn!(summary, false);
    templates_fn!(history, false);
    templates_fn!(commit, false);
    templates_fn!(branches, false);
    templates_fn!(branch, false);
    templates_fn!(tags, false);
    templates_fn!(tag, false);
    templates_fn!(files, false);
    templates_fn!(file, false);
    templates_fn!(dir, false);
    templates_fn!(error, false);

    fn canonicalize_and_create(&self, path: &Path, is_dir: bool) -> PathBuf {
        let mut canonical_path = self.output_root.clone()
            .canonicalize().expect(&format!(
                "ERROR: unable to canonicalize output path: {}",
                self.output_root.display()));
        canonical_path.push(path);
        match is_dir {
            true => {
                let _ = create_dir_all(&canonical_path);
            }
            false => {
                if let Some(dir) = canonical_path.parent() {
                    let _ = create_dir_all(dir);
                }
            }
        }
        canonical_path
    }

    pub fn output_dir(&self) -> PathBuf {
        self.output_root.clone().canonicalize()
            .expect(&format!("ERROR: unable to canonicalize output path: {}", self.output_root.display()))
    }

    pub fn template_dir(&self) -> PathBuf {
        self.template_root.clone().canonicalize()
            .expect(&format!("ERROR: unable to canonicalize template path: {}", self.template_root.display()))
    }

    pub fn has_files(&self) -> bool {
        match &self.templates {
            Some(template) => template.iter().filter(|x| x.kind == GitsyTemplateType::file).count() > 0,
            _ => false,
        }
    }

    pub fn asset<P: AsRef<Path>>(&self, asset: &P, parsed_repo: Option<&GitRepo>, repo: Option<&Repository>) -> PathBuf {
        let tmpl_path = asset.as_ref().to_path_buf();
        let asset_path = substitute_path_vars(&tmpl_path, parsed_repo, Some(self));
        let full_path = match repo {
            Some(repo) => {
                let mut full_path = repo.path().to_owned();
                full_path.push(asset_path);
                full_path
            },
            _ => {
                asset_path
            }
        };
        full_path
    }

    pub fn create(&self) {
        louder!("Creating output directory: {}", self.output_root.display());
        let _ = create_dir(self.output_root.to_str().expect(&format!("ERROR: output path invalid: {}", self.output_root.display())));
    }

    pub fn clean(&self) {
        if !self.output_root.exists() {
            return;
        }
        louder!("Cleaning output directory: {}", self.output_root.display());
        let dir: PathBuf = PathBuf::from(&self.output_dir());
        assert!(dir.is_dir(), "ERROR: Output directory is... not a directory? {}", dir.display());
        remove_dir_all(&dir)
            .expect(&format!("ERROR: failed to clean output directory: {}", dir.display()));
    }

    pub fn to_relative<P: AsRef<Path>>(&self, path: &P) -> String {
        let path = path.as_ref().to_str()
            .expect(&format!("ERROR: Unable to make path relative: {}",
                             path.as_ref().display()));
        let path_buf = PathBuf::from(path);
        path_buf.strip_prefix(self.output_dir())
            .expect(&format!("ERROR: Unable to make path relative: {}", path))
            .to_str()
            .expect(&format!("ERROR: Unable to make path relative: {}", path))
            .to_string()
    }

    pub fn assert_valid<P: AsRef<Path>>(&self, path: &P) -> bool {
        let path = path.as_ref().to_str()
            .expect(&format!("ERROR: attempted to write unrecognizeable path: {}", path.as_ref().display()));
        // Ensure that the requested output path is actually a child
        // of the output directory, as a sanity check to ensure we
        // aren't writing out of bounds.
        let canonical_root = self.output_root.canonicalize().expect(&format!(
            "Cannot find canonical version of output path: {}",
            self.output_root.display()
        ));
        let canonical_path = PathBuf::from(path);
        let has_relative_dirs = canonical_path
            .ancestors()
            .any(|x| x.file_name().is_none() && x != Path::new("/"));
        assert!(
            canonical_path.is_absolute(),
            "ERROR: write_rendered called with a relative path: {}",
            path
        );
        assert!(
            !has_relative_dirs,
            "ERROR: write_rendered called with a relative path: {}",
            path
        );
        let _ = canonical_path
            .ancestors()
            .find(|x| x == &canonical_root)
            .expect(&format!(
                "Output file {} not contained in output path: {}",
                canonical_path.display(),
                canonical_root.display()
            ));
        true
    }
}

#[derive(Clone, Deserialize, Default, Debug)]
pub struct GitsySettingsRepo {
    pub path: PathBuf,
    pub name: Option<String>,
    pub description: Option<String>,
    pub clone_url: Option<String>,
    pub website: Option<String>,
    pub branch: Option<String>,
    pub readme_files: Option<Vec<String>>,
    pub asset_files: Option<Vec<String>>,
    pub render_markdown: Option<bool>,
    pub syntax_highlight: Option<bool>,
    pub syntax_highlight_theme: Option<String>,
    pub attributes: Option<BTreeMap<String, toml::Value>>,
    pub paginate_history: Option<usize>,
    pub paginate_branches: Option<usize>,
    pub paginate_tags: Option<usize>,
    pub limit_history: Option<usize>,
    pub limit_commits: Option<usize>,
    pub limit_branches: Option<usize>,
    pub limit_tags: Option<usize>,
    pub limit_tree_depth: Option<usize>,
    pub limit_file_size: Option<usize>,
    pub limit_repo_size: Option<usize>,
    pub limit_total_size: Option<usize>,
    pub limit_context: Option<usize>,
    pub limit_diffs: Option<usize>,
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

pub type GitsyRepoDescriptions = HashSet<GitsySettingsRepo>;

#[derive(Deserialize, Debug)]
#[allow(dead_code)]
pub struct GitsySettings {
    pub recursive_repo_dirs: Option<Vec<PathBuf>>,
    pub site_name: Option<String>,
    pub site_url: Option<String>,
    pub site_description: Option<String>,
    pub clone_url: Option<String>,
    pub readme_files: Option<Vec<String>>,
    pub asset_files: Option<Vec<String>>,
    pub branch: Option<String>,
    pub paginate_history: Option<usize>,
    pub paginate_branches: Option<usize>,
    pub paginate_tags: Option<usize>,
    pub threads: Option<usize>,
    pub limit_history: Option<usize>,
    pub limit_commits: Option<usize>,
    pub limit_branches: Option<usize>,
    pub limit_tags: Option<usize>,
    pub limit_tree_depth: Option<usize>,
    pub limit_file_size: Option<usize>,
    pub limit_repo_size: Option<usize>,
    pub limit_total_size: Option<usize>,
    pub limit_context: Option<usize>,
    pub limit_diffs: Option<usize>,
    pub render_markdown: Option<bool>,
    pub syntax_highlight: Option<bool>,
    pub syntax_highlight_theme: Option<String>,
    #[serde(rename(deserialize = "gitsy_outputs"))]
    pub outputs: GitsySettingsOutputs,
    #[serde(rename(deserialize = "gitsy_extra"))]
    pub extra: Option<BTreeMap<String, toml::Value>>,
}

impl GitsySettings {
    pub fn new(cli: &GitsyCli) -> (GitsySettings, GitsyRepoDescriptions) {
        // Parse the known settings directly into their struct
        let toml = read_to_string(&cli.path).expect(&format!("Configuration file not found: {}", cli.path.display()));
        let mut settings: GitsySettings = toml::from_str(&toml).expect("Configuration file is invalid.");
        if cli.is_local {
            // removing the site URL falls back to using the local directory
            settings.site_url = None;
        }

        // Settings are valid, so let's move into the directory with the config file
        if cli.dir.to_str().unwrap_or_default().len() > 0 {
            // empty string means current directory
            std::env::set_current_dir(&cli.dir)
                .expect(&format!("Unable to set working directory to: {}", cli.dir.display()));
        }

        // Get a list of all remaining TOML "tables" in the file.
        // These are the user-supplied individual repositories.
        let reserved_keys = vec!["gitsy_templates", "gitsy_outputs", "gitsy_extra"];
        let settings_raw: HashMap<String, toml::Value> = toml::from_str(&toml).expect("blah");
        let table_keys: Vec<String> = settings_raw
            .iter()
            .filter_map(|x| match x.1.is_table() {
                true => match reserved_keys.contains(&x.0.as_str()) {
                    false => Some(x.0.clone()),
                    true => None,
                },
                false => None,
            })
            .collect();

        // Try to convert each unknown "table" into a repo struct, and
        // save the ones that are successful.  If no repo name is
        // specified, use the TOML table name.
        let mut repo_descriptions: HashSet<GitsySettingsRepo> = HashSet::new();
        macro_rules! global_to_repo {
            ($settings:ident, $repo:ident, $field:ident) => {
                if $repo.$field.is_none() {
                    $repo.$field = $settings.$field.clone()
                }
            };
        }
        for k in &table_keys {
            let v = settings_raw.get(k).unwrap();
            match toml::from_str::<GitsySettingsRepo>(&v.to_string()) {
                Ok(mut repo) => {
                    if repo.name.is_none() {
                        repo.name = Some(k.clone());
                    }
                    if repo.clone_url.is_none() {
                        repo.clone_url = match settings.clone_url.as_ref() {
                            Some(url) => Some(url.replace("%REPO%", repo.name.as_deref().unwrap_or_default())),
                            _ => None,
                        };
                    }
                    global_to_repo!(settings, repo, branch);
                    global_to_repo!(settings, repo, readme_files);
                    global_to_repo!(settings, repo, render_markdown);
                    global_to_repo!(settings, repo, syntax_highlight);
                    global_to_repo!(settings, repo, syntax_highlight_theme);
                    global_to_repo!(settings, repo, paginate_history);
                    global_to_repo!(settings, repo, paginate_branches);
                    global_to_repo!(settings, repo, paginate_tags);
                    global_to_repo!(settings, repo, limit_history);
                    global_to_repo!(settings, repo, limit_commits);
                    global_to_repo!(settings, repo, limit_branches);
                    global_to_repo!(settings, repo, limit_tags);
                    global_to_repo!(settings, repo, limit_tree_depth);
                    global_to_repo!(settings, repo, limit_file_size);
                    global_to_repo!(settings, repo, limit_repo_size);
                    global_to_repo!(settings, repo, limit_total_size);
                    global_to_repo!(settings, repo, limit_context);
                    global_to_repo!(settings, repo, limit_diffs);

                    repo_descriptions.insert(repo);
                }
                Err(e) => {
                    error!("Failed to parse repo [{}]: {:?}", k, e);
                }
            }
        }

        match &settings.recursive_repo_dirs {
            Some(dirs) => {
                for parent in dirs {
                    for dir in read_dir(parent).expect("Repo directory not found.") {
                        let dir = dir.expect("Repo contains invalid entries");
                        let name: String = dir.file_name().to_string_lossy().to_string();
                        let clone_url = match settings.clone_url.as_ref() {
                            Some(url) => Some(url.replace("%REPO%", &name)),
                            _ => None,
                        };
                        repo_descriptions.insert(GitsySettingsRepo {
                            path: dir.path().clone(),
                            name: Some(name),
                            clone_url,
                            readme_files: settings.readme_files.clone(),
                            branch: settings.branch.clone(),
                            render_markdown: settings.render_markdown.clone(),
                            syntax_highlight: settings.syntax_highlight.clone(),
                            syntax_highlight_theme: settings.syntax_highlight_theme.clone(),
                            paginate_history: settings.paginate_history.clone(),
                            paginate_branches: settings.paginate_branches.clone(),
                            paginate_tags: settings.paginate_tags.clone(),
                            limit_history: settings.limit_history.clone(),
                            limit_commits: settings.limit_commits.clone(),
                            limit_branches: settings.limit_branches.clone(),
                            limit_tags: settings.limit_tags.clone(),
                            limit_tree_depth: settings.limit_tree_depth.clone(),
                            limit_file_size: settings.limit_file_size.clone(),
                            limit_repo_size: settings.limit_repo_size.clone(),
                            limit_total_size: settings.limit_total_size.clone(),
                            limit_context: settings.limit_context.clone(),
                            limit_diffs: settings.limit_diffs.clone(),
                            ..Default::default()
                        });
                    }
                }
            }
            _ => {}
        }

        if cli.repos.len() > 0 {
            repo_descriptions.clear();
            for dir in &cli.repos {
                let name: String = dir
                    .file_name()
                    .expect(&format!("Invalid repository path: {}", dir.display()))
                    .to_string_lossy()
                    .to_string();
                let clone_url = match settings.clone_url.as_ref() {
                    Some(url) => Some(url.replace("%REPO%", &name)),
                    _ => None,
                };
                repo_descriptions.insert(GitsySettingsRepo {
                    path: dir.clone(),
                    name: Some(name),
                    clone_url,
                    readme_files: settings.readme_files.clone(),
                    branch: settings.branch.clone(),
                    render_markdown: settings.render_markdown.clone(),
                    syntax_highlight: settings.syntax_highlight.clone(),
                    syntax_highlight_theme: settings.syntax_highlight_theme.clone(),
                    paginate_history: settings.paginate_history.clone(),
                    paginate_branches: settings.paginate_branches.clone(),
                    paginate_tags: settings.paginate_tags.clone(),
                    limit_history: settings.limit_history.clone(),
                    limit_commits: settings.limit_commits.clone(),
                    limit_branches: settings.limit_branches.clone(),
                    limit_tags: settings.limit_tags.clone(),
                    limit_tree_depth: settings.limit_tree_depth.clone(),
                    limit_file_size: settings.limit_file_size.clone(),
                    limit_repo_size: settings.limit_repo_size.clone(),
                    limit_total_size: settings.limit_total_size.clone(),
                    limit_context: settings.limit_context.clone(),
                    limit_diffs: settings.limit_diffs.clone(),
                    ..Default::default()
                });
            }
        }

        (settings, repo_descriptions)
    }

    pub fn paginate_history(&self) -> usize {
        match self.paginate_history.unwrap_or(usize::MAX) {
            x if x == 0 => usize::MAX,
            x => x,
        }
    }

    pub fn paginate_branches(&self) -> usize {
        match self.paginate_branches.unwrap_or(usize::MAX) {
            x if x == 0 => usize::MAX,
            x => x,
        }
    }

    pub fn paginate_tags(&self) -> usize {
        match self.paginate_tags.unwrap_or(usize::MAX) {
            x if x == 0 => usize::MAX,
            x => x,
        }
    }
}

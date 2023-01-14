use crate::error;
use crate::git::{GitFile, GitObject, GitRepo};
use clap::Parser;
use serde::Deserialize;
use std::collections::{BTreeMap, HashMap, HashSet};
use std::fs::{create_dir, create_dir_all, read_dir, remove_dir_all, read_to_string};
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
pub struct GitsySettingsTemplates {
    pub path: PathBuf,
    pub repo_list: Option<String>,
    pub repo_summary: Option<String>,
    pub history: Option<String>,
    pub commit: Option<String>,
    pub branches: Option<String>,
    pub branch: Option<String>,
    pub tags: Option<String>,
    pub tag: Option<String>,
    pub files: Option<String>,
    pub file: Option<String>,
    pub dir: Option<String>,
    pub error: Option<String>,
}

#[derive(Deserialize, Debug)]
pub struct GitsySettingsOutputs {
    pub path: PathBuf,
    pub cloned_repos: Option<String>,
    pub repo_list: Option<String>,
    pub repo_summary: Option<String>,
    pub history: Option<String>,
    pub commit: Option<String>,
    pub branches: Option<String>,
    pub branch: Option<String>,
    pub tags: Option<String>,
    pub tag: Option<String>,
    pub files: Option<String>,
    pub file: Option<String>,
    pub dir: Option<String>,
    pub error: Option<String>,
    pub syntax_css: Option<String>,
    pub global_assets: Option<String>,
    pub repo_assets: Option<String>,
}

macro_rules! output_path_fn {
    ($var:ident, $obj:ty, $id:ident, $is_dir:expr, $default:expr) => {
        pub fn $var(&self, repo: Option<&GitRepo>, obj: Option<&$obj>) -> String {
            let tmpl_str = self.$var.as_deref().unwrap_or($default).to_string();
            let tmpl_str = match (tmpl_str.contains("%REPO%"), repo.is_some()) {
                (true, true) => {
                    let name = repo.map(|x| &x.name).unwrap();
                    tmpl_str.replace("%REPO%", name)
                }
                (true, false) => {
                    panic!("%REPO% variable not available for output path: {}", tmpl_str);
                }
                _ => tmpl_str,
            };
            let tmpl_str = match (tmpl_str.contains("%ID%"), obj.is_some()) {
                (true, true) => {
                    let name = obj.map(|x| &x.$id).unwrap();
                    tmpl_str.replace("%ID%", name)
                }
                (true, false) => {
                    panic!("%ID% variable not available for output path: {}", tmpl_str);
                }
                _ => tmpl_str,
            };
            let tmpl = PathBuf::from(tmpl_str);
            let mut path = self.path.clone().canonicalize().expect(&format!(
                "ERROR: unable to canonicalize output path: {}",
                self.path.display()
            ));
            path.push(tmpl);
            match $is_dir {
                true => {
                    let _ = create_dir_all(&path);
                }
                false => {
                    if let Some(dir) = path.parent() {
                        let _ = create_dir_all(dir);
                    }
                }
            }
            path.to_str()
                .expect(&format!("Output is not a valid path: {}", path.display()))
                .into()
        }
    };
}
//step_map_first!(boil_in_wort, Boil, Wort, |b: &Boil| { b.wort_start() });

#[rustfmt::skip]
impl GitsySettingsOutputs {
    output_path_fn!(repo_list,       GitObject, full_hash, false, "repos.html");
    output_path_fn!(repo_summary,    GitObject, full_hash, false, "%REPO%/summary.html");
    output_path_fn!(history,         GitObject, full_hash, false, "%REPO%/history%PAGE%.html");
    output_path_fn!(commit,          GitObject, full_hash, false, "%REPO%/commit/%ID%.html");
    output_path_fn!(branches,        GitObject, full_hash, false, "%REPO%/branches%PAGE%.html");
    output_path_fn!(branch,          GitObject, full_hash, false, "%REPO%/branch/%ID%.html");
    output_path_fn!(tags,            GitObject, full_hash, false, "%REPO%/tags%PAGE%.html");
    output_path_fn!(tag,             GitObject, full_hash, false, "%REPO%/tag/%ID%.html");
    output_path_fn!(files,           GitObject, full_hash, false, "%REPO%/files.html");
    output_path_fn!(file,            GitFile,   id,        false, "%REPO%/file/%ID%.html");
    output_path_fn!(syntax_css,      GitObject, full_hash, false, "%REPO%/file/syntax.css");
    output_path_fn!(dir,             GitFile,   id,        false, "%REPO%/dir/%ID%.html");
    output_path_fn!(error,           GitObject, full_hash, false, "404.html");
    output_path_fn!(global_assets,   GitObject, full_hash, true,  "assets/");
    output_path_fn!(repo_assets,     GitObject, full_hash, true,  "%REPO%/assets/");

    pub fn output_dir(&self) -> String {
        self.path.clone().canonicalize()
            .expect(&format!("ERROR: unable to canonicalize output path: {}", self.path.display()))
            .to_str().expect(&format!("ERROR: unable to parse output path: {}", self.path.display()))
            .to_string()
    }

    pub fn create(&self) {
        let _ = create_dir(self.path.to_str().expect(&format!("ERROR: output path invalid: {}", self.path.display())));
    }

    pub fn clean(&self) {
        if !self.path.exists() {
            return;
        }
        let dir: PathBuf = PathBuf::from(&self.output_dir());
        assert!(dir.is_dir(), "ERROR: Output directory is... not a directory? {}", dir.display());
        remove_dir_all(&dir)
            .expect(&format!("ERROR: failed to clean output directory: {}", dir.display()));
    }

    pub fn to_relative(&self, path: &str) -> String {
        let path_buf = PathBuf::from(path);
        path_buf.strip_prefix(self.output_dir())
            .expect(&format!("ERROR: Unable to make path relative: {}", path))
            .to_str()
            .expect(&format!("ERROR: Unable to make path relative: {}", path))
            .to_string()
    }
}

#[derive(Clone, Deserialize, Default, Debug)]
pub struct GitsySettingsRepo {
    pub path: PathBuf,
    pub name: Option<String>,
    pub description: Option<String>,
    pub website: Option<String>,
    pub branch: Option<String>,
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
    pub asset_files: Option<Vec<String>>,
    pub branch: Option<String>,
    #[serde(rename(deserialize = "gitsy_templates"))]
    pub templates: GitsySettingsTemplates,
    #[serde(rename(deserialize = "gitsy_outputs"))]
    pub outputs: GitsySettingsOutputs,
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
    pub render_markdown: Option<bool>,
    pub syntax_highlight: Option<bool>,
    pub syntax_highlight_theme: Option<String>,
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
                    global_to_repo!(settings, repo, branch);
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
                        repo_descriptions.insert(GitsySettingsRepo {
                            path: dir.path().clone(),
                            name: Some(name),
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
                let name: String = dir.file_name()
                    .expect(&format!("Invalid repository path: {}", dir.display()))
                    .to_string_lossy().to_string();
                repo_descriptions.insert(GitsySettingsRepo {
                    path: dir.clone(),
                    name: Some(name),
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

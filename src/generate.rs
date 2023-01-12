use crate::{
    error,
    git::{dir_listing, parse_repo, GitFile, GitRepo, GitsyMetadata},
    loud, louder, loudest, normal, normal_noln,
    settings::{GitsyCli, GitsyRepoDescriptions, GitsySettings, GitsySettingsRepo},
    template::{DirFilter, FileFilter, Pagination, TsDateFn, TsTimestampFn},
    util::GitsyError,
};
use git2::{Error, Repository};
use rayon::prelude::*;
use std::cmp;
use std::fs::{create_dir, File};
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Instant;
use tera::{Context, Tera};

#[cfg(feature = "markdown")]
use pulldown_cmark::{html, Options, Parser as MdParser};

#[cfg(any(feature = "highlight", feature = "highlight_fast"))]
use syntect::{
    highlighting::ThemeSet,
    html::{css_for_theme_with_class_style, ClassStyle, ClassedHTMLGenerator},
    parsing::SyntaxSet,
    util::LinesWithEndings,
};

macro_rules! size_check {
    ($settings:ident, $cur:expr, $total:expr, $action:expr) => {
        let cur: usize = $cur;
        if cur > $settings.limit_repo_size.unwrap_or(usize::MAX) {
            $action;
        }
        let total: usize = $total;
        if total.saturating_add($cur) > $settings.limit_total_size.unwrap_or(usize::MAX) {
            $action;
        }
    };
}

pub struct GitsyGenerator {
    cli: GitsyCli,
    settings: GitsySettings,
    repo_descriptions: GitsyRepoDescriptions,
}

impl GitsyGenerator {
    pub fn new(cli: GitsyCli, settings: GitsySettings, repo_descriptions: GitsyRepoDescriptions) -> GitsyGenerator {
        GitsyGenerator {
            cli,
            settings,
            repo_descriptions,
        }
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
            _ => {
                return contents.to_string();
            }
        };
        let mut html_generator = ClassedHTMLGenerator::new_with_class_style(syntax, &syntax_set, ClassStyle::Spaced);
        for line in LinesWithEndings::from(contents) {
            match html_generator.parse_html_for_line_which_includes_newline(line) {
                Ok(_) => {}
                Err(_) => {
                    error!("Warning: failed to apply syntax highlighting.");
                    return contents.to_string();
                }
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
                            let (cstr, rendered, pre) = (GitsyGenerator::parse_markdown(&cstr), true, false);
                            (cstr, rendered, pre)
                        }
                        #[cfg(any(feature = "highlight", feature = "highlight_fast"))]
                        Some(x) if settings.syntax_highlight.unwrap_or(false) => {
                            loudest!(" - syntax highlighting {}", path.display());
                            (
                                GitsyGenerator::syntax_highlight(&cstr, x.to_string_lossy().to_string().as_str()),
                                true,
                                true,
                            )
                        }
                        _ => (cstr, false, true),
                    };
                    file.contents_safe = rendered;
                    file.contents_preformatted = pre;
                    Some(content)
                }
                true => Some(format!("[Binary data ({} bytes)]", blob.content().len())),
            };
        }
        Ok(file)
    }

    fn write_rendered(&self, path: &str, rendered: &str) -> usize {
        // Ensure that the requested output path is actually a child
        // of the output directory, as a sanity check to ensure we
        // aren't writing out of bounds.
        let canonical_root = self.settings.outputs.path.canonicalize().expect(&format!(
            "Cannot find canonical version of output path: {}",
            self.settings.outputs.path.display()
        ));
        let canonical_path = PathBuf::from(path);
        let has_relative_dirs = canonical_path.ancestors().any(|x| x.file_name().is_none() &&
                                                               x != Path::new("/"));
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

        // Write the file to disk
        let mut file = File::create(path).expect(&format!("Unable to write to output path: {}", path));
        file.write(rendered.as_bytes())
            .expect(&format!("Failed to save rendered html to path: {}", path));
        louder!(" - wrote file: {}", path);
        rendered.as_bytes().len()
    }

    fn tera_init(&self) -> Result<Tera, GitsyError> {
        let mut template_path = self.settings.templates.path.clone();
        template_path.push("**");
        template_path.push("*.html");
        let mut tera = Tera::new(&template_path.to_string_lossy().to_string())?;
        tera.register_filter("only_files", FileFilter {});
        tera.register_filter("only_dirs", DirFilter {});
        tera.register_function("ts_to_date", TsDateFn {});
        tera.register_function("ts_to_git_timestamp", TsTimestampFn {});
        Ok(tera)
    }

    pub fn generate(&self) -> Result<(), GitsyError> {
        let start_all = Instant::now();
        let tera = self.tera_init()?;

        // Create output directory
        let _ = create_dir(self.settings.outputs.path.to_str().expect("Output path invalid."));

        let generated_dt = chrono::offset::Local::now();
        let mut global_bytes = 0;
        let mut total_bytes = 0;
        let mut repos: Vec<GitRepo> = vec![];

        if self.repo_descriptions.len() == 0 {
            panic!(
                "No Git repositories defined!  Please check your configuration file ({})",
                self.cli.path.display()
            );
        }

        // Sort the repositories by name
        let mut repo_vec: Vec<GitsySettingsRepo> = self.repo_descriptions.iter().cloned().collect();
        repo_vec.sort_by(|x, y| {
            x.name
                .as_deref()
                .map(|n| n.cmp(&y.name.as_deref().unwrap_or_default()))
                .unwrap_or(cmp::Ordering::Equal)
        });
        // Find the one with the longest name, for pretty printing
        let global_name = "repo list";
        let longest_repo_name = repo_vec
            .iter()
            .fold(0, |acc, x| {
                cmp::max(acc, x.name.as_deref().map(|n| n.len()).unwrap_or(0))
            })
            .max(global_name.len());

        loudest!("Global settings:\n{:#?}", &self.settings);

        // Iterate over each repository, generating outputs
        for repo_desc in &repo_vec {
            loudest!("Repo settings:\n{:#?}", &repo_desc);
            let start_repo = Instant::now();
            let mut repo_bytes = 0;
            let name = repo_desc.name.as_deref().expect("A configured repository has no name!");

            let repo_path = match &repo_desc.path {
                url if url.starts_with("https://") || url.to_str().unwrap_or_default().contains("@") => {
                    if self.settings.outputs.cloned_repos.is_none() {
                        error!(
                            "ERROR: Found remote repo [{}], but `cloned_repos` directory not configured.",
                            name
                        );
                        continue;
                    };
                    let clone_path: PathBuf = [self.settings.outputs.cloned_repos.as_deref().unwrap(), name]
                        .iter()
                        .collect();
                    match Repository::open(&clone_path) {
                        Ok(r) => {
                            // Repo already cloned, so update all refs
                            let refs: Vec<String> = r
                                .references()
                                .expect(&format!("Unable to enumerate references for repo [{}]", name))
                                .map(|x| {
                                    x.expect(&format!("Found invalid reference in repo [{}]", name))
                                        .name()
                                        .expect(&format!("Found unnamed reference in repo: [{}]", name))
                                        .to_string()
                                })
                                .collect();
                            r.find_remote("origin")
                                .expect(&format!("Clone of repo [{}] missing `origin` remote.", name))
                                .fetch(&refs, None, None)
                                .expect(&format!("Failed to fetch updates from remote repo [{}]", name));
                            clone_path.to_string_lossy().to_string()
                        }
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
                        Ok(m) if m.is_dir() => {}
                        _ => {
                            error!(
                                "ERROR: local repository [{}]: directory not found: {}",
                                name,
                                dir.display()
                            );
                            continue;
                        }
                    }
                    dir.to_string_lossy().to_string()
                }
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
            if let Some(extra) = &self.settings.extra {
                local_ctx
                    .try_insert("extra", extra)
                    .expect("Failed to add extra settings to template engine.");
            }
            if let Some(site_name) = &self.settings.site_name {
                local_ctx.insert("site_name", site_name);
            }
            if let Some(site_url) = &self.settings.site_url {
                local_ctx.insert("site_url", site_url);
            }
            if let Some(site_description) = &self.settings.site_description {
                local_ctx.insert("site_description", site_description);
            }
            local_ctx.insert("site_generated_ts", &generated_dt.timestamp());
            local_ctx.insert("site_generated_offset", &generated_dt.offset().local_minus_utc());

            if let Some(templ_file) = self.settings.templates.repo_summary.as_deref() {
                match tera.render(templ_file, &local_ctx) {
                    Ok(rendered) => {
                        repo_bytes +=
                            self.write_rendered(&self.settings.outputs.repo_summary(Some(&summary), None), &rendered);
                    }
                    Err(x) => match x.kind {
                        _ => error!("ERROR: {:?}", x),
                    },
                }
            }

            if let Some(templ_file) = self.settings.templates.branches.as_deref() {
                let mut paged_ctx = local_ctx.clone();
                paged_ctx.remove("branches");
                let pages = summary
                    .branches
                    .chunks(self.settings.paginate_branches());
                let page_count = pages.len();
                for (idx, page) in pages.enumerate() {
                    let pagination =
                        Pagination::new(idx + 1, page_count, &self.settings.outputs.branches(Some(&summary), None));
                    paged_ctx.insert("page", &pagination.with_relative_paths());
                    paged_ctx.insert("branches", &page);
                    match tera.render(templ_file, &paged_ctx) {
                        Ok(rendered) => {
                            repo_bytes += self.write_rendered(&pagination.cur_page, &rendered);
                        }
                        Err(x) => match x.kind {
                            _ => error!("ERROR: {:?}", x),
                        },
                    }
                    paged_ctx.remove("page");
                    paged_ctx.remove("branches");
                }
            }

            for branch in &summary.branches {
                size_check!(repo_desc, repo_bytes, total_bytes, break);
                local_ctx.insert("branch", branch);
                if let Some(templ_file) = self.settings.templates.branch.as_deref() {
                    match tera.render(templ_file, &local_ctx) {
                        Ok(rendered) => {
                            repo_bytes += self
                                .write_rendered(&self.settings.outputs.branch(Some(&summary), Some(branch)), &rendered);
                        }
                        Err(x) => match x.kind {
                            _ => error!("ERROR: {:?}", x),
                        },
                    }
                }
                local_ctx.remove("branch");
            }

            if let Some(templ_file) = self.settings.templates.tags.as_deref() {
                let mut paged_ctx = local_ctx.clone();
                paged_ctx.remove("tags");
                let pages = summary
                    .tags
                    .chunks(self.settings.paginate_tags());
                let page_count = pages.len();
                for (idx, page) in pages.enumerate() {
                    let pagination =
                        Pagination::new(idx + 1, page_count, &self.settings.outputs.tags(Some(&summary), None));
                    paged_ctx.insert("page", &pagination.with_relative_paths());
                    paged_ctx.insert("tags", &page);
                    match tera.render(templ_file, &paged_ctx) {
                        Ok(rendered) => {
                            repo_bytes += self.write_rendered(&pagination.cur_page, &rendered);
                        }
                        Err(x) => match x.kind {
                            _ => error!("ERROR: {:?}", x),
                        },
                    }
                    paged_ctx.remove("page");
                    paged_ctx.remove("tags");
                }
            }

            for tag in &summary.tags {
                size_check!(repo_desc, repo_bytes, total_bytes, break);
                local_ctx.insert("tag", tag);
                if let Some(tagged_id) = tag.tagged_id.as_ref() {
                    if let Some(commit) = summary.commits.get(tagged_id) {
                        local_ctx.insert("commit", &commit);
                    }
                }
                if let Some(templ_file) = self.settings.templates.tag.as_deref() {
                    match tera.render(templ_file, &local_ctx) {
                        Ok(rendered) => {
                            repo_bytes +=
                                self.write_rendered(&self.settings.outputs.tag(Some(&summary), Some(tag)), &rendered);
                        }
                        Err(x) => match x.kind {
                            _ => error!("ERROR: {:?}", x),
                        },
                    }
                }
                local_ctx.remove("tag");
                local_ctx.remove("commit");
            }

            if let Some(templ_file) = self.settings.templates.history.as_deref() {
                let mut paged_ctx = local_ctx.clone();
                paged_ctx.remove("history");
                let pages = summary
                    .history
                    .chunks(self.settings.paginate_history());
                let page_count = pages.len();
                for (idx, page) in pages.enumerate() {
                    let pagination =
                        Pagination::new(idx + 1, page_count, &self.settings.outputs.history(Some(&summary), None));
                    paged_ctx.insert("page", &pagination.with_relative_paths());
                    paged_ctx.insert("history", &page);
                    match tera.render(templ_file, &paged_ctx) {
                        Ok(rendered) => {
                            repo_bytes += self.write_rendered(&pagination.cur_page, &rendered);
                        }
                        Err(x) => match x.kind {
                            _ => error!("ERROR: {:?}", x),
                        },
                    }
                    paged_ctx.remove("page");
                    paged_ctx.remove("history");
                }
            }

            for (_id, commit) in &summary.commits {
                size_check!(repo_desc, repo_bytes, total_bytes, break);
                local_ctx
                    .try_insert("commit", &commit)
                    .expect("Failed to add commit to template engine.");
                if let Some(templ_file) = self.settings.templates.commit.as_deref() {
                    match tera.render(templ_file, &local_ctx) {
                        Ok(rendered) => {
                            repo_bytes += self
                                .write_rendered(&self.settings.outputs.commit(Some(&summary), Some(commit)), &rendered);
                        }
                        Err(x) => match x.kind {
                            _ => error!("ERROR: {:?}", x),
                        },
                    }
                }
                local_ctx.remove("commit");
            }

            #[cfg(any(feature = "highlight", feature = "highlight_fast"))]
            if self.settings.templates.file.is_some() {
                let ts = ThemeSet::load_defaults();
                let theme = ts
                    .themes
                    .get(
                        repo_desc
                            .syntax_highlight_theme
                            .as_deref()
                            .unwrap_or("base16-ocean.light"),
                    )
                    .expect("Invalid syntax highlighting theme specified.");
                let css: String = css_for_theme_with_class_style(theme, syntect::html::ClassStyle::Spaced)
                    .expect("Invalid syntax highlighting theme specified.");
                repo_bytes +=
                    self.write_rendered(&self.settings.outputs.syntax_css(Some(&summary), None), css.as_str());
            }

            // TODO: parallelize the rest of the processing steps.  This one is
            // done first because syntax highlighting is very slow.
            let files: Vec<&GitFile> = summary.all_files.iter().filter(|x| x.kind == "file").collect();
            let atomic_bytes: AtomicUsize = AtomicUsize::new(repo_bytes);
            let _ = files
                .par_iter()
                .fold(
                    || Some(0),
                    |acc, file| {
                        // These two have to be recreated.  Cloning the Tera context is expensive.
                        let repo = Repository::open(&repo_path).expect("Unable to find git repository.");
                        let mut local_ctx = local_ctx.clone();

                        let mut local_bytes = 0;
                        let cur_repo_bytes = atomic_bytes.load(Ordering::Relaxed);
                        size_check!(repo_desc, cur_repo_bytes, total_bytes, return None);
                        let file = match file.size < repo_desc.limit_file_size.unwrap_or(usize::MAX) {
                            true => GitsyGenerator::fill_file_contents(&repo, &file, &repo_desc)
                                .expect("Failed to parse file."),
                            false => (*file).clone(),
                        };
                        local_ctx
                            .try_insert("file", &file)
                            .expect("Failed to add file to template engine.");
                        if let Some(templ_file) = self.settings.templates.file.as_deref() {
                            match tera.render(templ_file, &local_ctx) {
                                Ok(rendered) => {
                                    local_bytes = self.write_rendered(
                                        &self.settings.outputs.file(Some(&summary), Some(&file)),
                                        &rendered,
                                    );
                                    atomic_bytes.fetch_add(local_bytes, Ordering::Relaxed);
                                }
                                Err(x) => match x.kind {
                                    _ => error!("ERROR: {:?}", x),
                                },
                            }
                        }
                        local_ctx.remove("file");
                        Some(acc.unwrap() + local_bytes)
                    },
                )
                .while_some() // allow short-circuiting if size limit is reached
                .sum::<usize>();
            repo_bytes = atomic_bytes.load(Ordering::Relaxed);

            for dir in summary.all_files.iter().filter(|x| x.kind == "dir") {
                size_check!(repo_desc, repo_bytes, total_bytes, break);
                if dir.tree_depth >= repo_desc.limit_tree_depth.unwrap_or(usize::MAX) - 1 {
                    continue;
                }
                let listing = dir_listing(&repo, &dir).expect("Failed to parse file.");
                local_ctx
                    .try_insert("files", &listing)
                    .expect("Failed to add dir to template engine.");
                if let Some(templ_file) = self.settings.templates.dir.as_deref() {
                    match tera.render(templ_file, &local_ctx) {
                        Ok(rendered) => {
                            repo_bytes +=
                                self.write_rendered(&self.settings.outputs.dir(Some(&summary), Some(dir)), &rendered);
                        }
                        Err(x) => match x.kind {
                            _ => error!("ERROR: {:?}", x),
                        },
                    }
                }
                local_ctx.remove("files");
            }

            if repo_desc.asset_files.is_some() {
                let target_dir = self.settings.outputs.repo_assets(Some(&summary), None);
                for src_file in repo_desc.asset_files.as_ref().unwrap() {
                    let src_file = PathBuf::from(repo_path.to_owned() + "/" + src_file);
                    let mut dst_file = PathBuf::from(&target_dir);
                    dst_file.push(src_file.file_name().expect(&format!(
                        "Failed to copy repo asset file: {} ({})",
                        src_file.display(),
                        repo_desc.name.as_deref().unwrap_or_default()
                    )));
                    std::fs::copy(&src_file, &dst_file).expect(&format!(
                        "Failed to copy repo asset file: {} ({})",
                        src_file.display(),
                        repo_desc.name.as_deref().unwrap_or_default()
                    ));
                    if let Ok(meta) = std::fs::metadata(dst_file) {
                        repo_bytes += meta.len() as usize;
                    }
                }
            }

            repos.push(summary);
            normal!(
                "{}done in {:.2}s ({} bytes)",
                match crate::util::VERBOSITY.load(Ordering::Relaxed) > 1 {
                    true => " - ",
                    _ => "",
                },
                start_repo.elapsed().as_secs_f32(),
                repo_bytes
            );
            total_bytes += repo_bytes;
            size_check!(repo_desc, 0, total_bytes, break); // break if total is exceeded
        }

        let start_global = Instant::now();
        normal_noln!(
            "[{}{}]... ",
            global_name,
            " ".repeat(longest_repo_name - global_name.len())
        );
        let mut global_ctx = Context::new();
        global_ctx
            .try_insert("repos", &repos)
            .expect("Failed to add repo to template engine.");
        if let Some(extra) = &self.settings.extra {
            global_ctx
                .try_insert("extra", extra)
                .expect("Failed to add extra settings to template engine.");
        }
        if let Some(site_name) = &self.settings.site_name {
            global_ctx.insert("site_name", site_name);
        }
        if let Some(site_url) = &self.settings.site_url {
            global_ctx.insert("site_url", site_url);
        }
        if let Some(site_description) = &self.settings.site_description {
            global_ctx.insert("site_description", site_description);
        }
        global_ctx.insert("site_generated_ts", &generated_dt.timestamp());
        global_ctx.insert("site_generated_offset", &generated_dt.offset().local_minus_utc());

        if let Some(templ_file) = self.settings.templates.repo_list.as_deref() {
            match tera.render(templ_file, &global_ctx) {
                Ok(rendered) => {
                    global_bytes += self.write_rendered(&self.settings.outputs.repo_list(None, None), &rendered);
                }
                Err(x) => match x.kind {
                    _ => error!("ERROR: {:?}", x),
                },
            }
        }

        if let Some(templ_file) = self.settings.templates.error.as_deref() {
            match tera.render(templ_file, &global_ctx) {
                Ok(rendered) => {
                    global_bytes += self.write_rendered(&self.settings.outputs.error(None, None), &rendered);
                }
                Err(x) => match x.kind {
                    _ => error!("ERROR: {:?}", x),
                },
            }
        }

        if self.settings.asset_files.is_some() {
            let target_dir = self.settings.outputs.global_assets(None, None);
            for src_file in self.settings.asset_files.as_ref().unwrap() {
                let src_file = PathBuf::from(src_file);
                let mut dst_file = PathBuf::from(&target_dir);
                dst_file.push(
                    src_file
                        .file_name()
                        .expect(&format!("Failed to copy asset file: {}", src_file.display())),
                );
                std::fs::copy(&src_file, &dst_file)
                    .expect(&format!("Failed to copy asset file: {}", src_file.display()));
                if let Ok(meta) = std::fs::metadata(dst_file) {
                    global_bytes += meta.len() as usize;
                }
            }
        }

        total_bytes += global_bytes;
        normal!(
            "done in {:.2}s ({} bytes)",
            start_global.elapsed().as_secs_f32(),
            global_bytes
        );
        loud!(
            "Wrote {} bytes in {:.2}s",
            total_bytes,
            start_all.elapsed().as_secs_f32()
        );
        Ok(())
    }
}

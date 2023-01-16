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
use crate::{
    error,
    git::{dir_listing, parse_repo, GitFile, GitRepo, GitsyMetadata},
    loud, louder, loudest, normal, normal_noln,
    settings::{GitsyCli, GitsyRepoDescriptions, GitsySettings, GitsySettingsRepo},
    template::{DirFilter, FileFilter, HexFilter, MaskFilter, OctFilter, Pagination, TsDateFn, TsTimestampFn, UrlStringFilter},
    util::{GitsyError, GitsyErrorKind, VERBOSITY},
};
use git2::{Error, Repository};
use rayon::prelude::*;
use chrono::{DateTime, Local};
use std::cmp;
use std::fs::File;
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
    tera: Option<Tera>,
    total_bytes: AtomicUsize,
    generated_dt: DateTime<Local>,
}

impl GitsyGenerator {
    pub fn new(cli: GitsyCli, settings: GitsySettings, repo_descriptions: GitsyRepoDescriptions) -> GitsyGenerator {
        GitsyGenerator {
            cli,
            settings,
            repo_descriptions,
            tera: None,
            total_bytes: AtomicUsize::new(0),
            generated_dt: chrono::offset::Local::now(),
        }
    }
    fn new_context(&self, repo: Option<&GitRepo>) -> Result<Context, GitsyError> {
        let mut ctx = match repo {
            Some(repo) => Context::from_serialize(repo)?,
            _ => Context::new(),
        };
        if let Some(extra) = &self.settings.extra {
            ctx
                .try_insert("extra", extra)
                .expect("Failed to add extra settings to template engine.");
        }
        if let Some(site_name) = &self.settings.site_name {
            ctx.insert("site_name", site_name);
        }
        if let Some(site_url) = &self.settings.site_url {
            ctx.insert("site_url", site_url);
        }
        if let Some(site_description) = &self.settings.site_description {
            ctx.insert("site_description", site_description);
        }
        ctx.insert("site_dir", &self.settings.outputs.output_dir());
        if self.settings.outputs.global_assets.is_some() {
            ctx.insert("site_assets", &self.settings.outputs.to_relative(&self.settings.outputs.global_assets::<GitFile>(None, None)));
        }
        ctx.insert("site_generated_ts", &self.generated_dt.timestamp());
        ctx.insert("site_generated_offset", &self.generated_dt.offset().local_minus_utc());
        Ok(ctx)
    }

    fn find_repo(&self, name: &str, repo_desc: &GitsySettingsRepo) -> Result<String, GitsyError> {
        let repo_path = match &repo_desc.path {
            url if url.starts_with("https://") || url.to_str().unwrap_or_default().contains("@") => {
                if self.settings.outputs.cloned_repos.is_none() {
                    return Err(GitsyError::kind(GitsyErrorKind::Settings,
                                                Some(&format!("ERROR: Found remote repo [{}], but `cloned_repos` directory not configured.", name))));
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
                        return Err(GitsyError::kind(GitsyErrorKind::Settings,
                                                    Some(&format!("ERROR: Local repository not found: {}", name))));
                    }
                }
                dir.to_string_lossy().to_string()
            }
        };
        Ok(repo_path)
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

    fn write_rendered<P: AsRef<Path>>(&self, path: &P, rendered: &str) -> usize {
        let path: &Path = path.as_ref();
        assert!(self.settings.outputs.assert_valid(&path),
                "ERROR: attempted to write invalid path: {}", path.display());
        // Write the file to disk
        let mut file = File::create(path).expect(&format!("Unable to write to output path: {}", path.display()));
        file.write(rendered.as_bytes())
            .expect(&format!("Failed to save rendered html to path: {}", path.display()));
        louder!(" - wrote file: {}", path.display());
        rendered.as_bytes().len()
    }

    fn tera_init(&self) -> Result<Tera, GitsyError> {
        let mut template_path = self.settings.outputs.template_dir();
        template_path.push("**");
        template_path.push("*.html");
        let mut tera = Tera::new(&template_path.to_string_lossy().to_string())?;
        tera.register_filter("only_files", FileFilter {});
        tera.register_filter("only_dirs", DirFilter {});
        tera.register_filter("hex", HexFilter {});
        tera.register_filter("oct", OctFilter {});
        tera.register_filter("mask", MaskFilter {});
        tera.register_filter("url_string", UrlStringFilter {});
        tera.register_function("ts_to_date", TsDateFn {});
        tera.register_function("ts_to_git_timestamp", TsTimestampFn {});
        Ok(tera)
    }

    pub fn gen_repo_list(&self, ctx: &Context) -> Result<usize, GitsyError> {
        let tera = self.tera.as_ref().expect("ERROR: generate called without a context!?");
        let mut global_bytes = 0;
        for (templ_path, out_path) in self.settings.outputs.repo_list::<GitRepo>(None, None) {
            let templ_path = templ_path.to_str().expect(&format!("ERROR: a summary template path is invalid: {}", templ_path.display()));
            let out_path = out_path.to_str().expect(&format!("ERROR: a summary output path is invalid: {}", out_path.display()));
            match tera.render(templ_path, &ctx) {
                Ok(rendered) => {
                    global_bytes += self.write_rendered(&out_path, &rendered);
                }
                Err(x) => match x.kind {
                    _ => error!("ERROR: {:?}", x),
                },
            }
        }
        Ok(global_bytes)
    }

    pub fn gen_error(&self, ctx: &Context) -> Result<usize, GitsyError> {
        let tera = self.tera.as_ref().expect("ERROR: generate called without a context!?");
        let mut global_bytes = 0;
        for (templ_path, out_path) in self.settings.outputs.error::<GitRepo>(None, None) {
            let templ_path = templ_path.to_str().expect(&format!("ERROR: a summary template path is invalid: {}", templ_path.display()));
            let out_path = out_path.to_str().expect(&format!("ERROR: a summary output path is invalid: {}", out_path.display()));
            match tera.render(templ_path, &ctx) {
                Ok(rendered) => {
                    global_bytes += self.write_rendered(&out_path, &rendered);
                }
                Err(x) => match x.kind {
                    _ => error!("ERROR: {:?}", x),
                },
            }
        }
        Ok(global_bytes)
    }

    pub fn gen_summary(&self, ctx: &Context, parsed_repo: &GitRepo, _repo_desc: &GitsySettingsRepo, _repo: &Repository) -> Result<usize, GitsyError> {
        let tera = self.tera.as_ref().expect("ERROR: generate called without a context!?");
        let mut repo_bytes = 0;
        for (templ_path, out_path) in self.settings.outputs.summary::<GitRepo>(Some(parsed_repo), None) {
            let templ_path = templ_path.to_str().expect(&format!("ERROR: a summary template path is invalid: {}", templ_path.display()));
            let out_path = out_path.to_str().expect(&format!("ERROR: a summary output path is invalid: {}", out_path.display()));
            match tera.render(templ_path, &ctx) {
                Ok(rendered) => {
                    repo_bytes +=
                        self.write_rendered(&out_path, &rendered);
                }
                Err(x) => match x.kind {
                    _ => error!("ERROR: {:?}", x),
                },
            }
        }
        Ok(repo_bytes)
    }

    pub fn gen_history(&self, ctx: &Context, parsed_repo: &GitRepo, _repo_desc: &GitsySettingsRepo, _repo: &Repository) -> Result<usize, GitsyError> {
        let tera = self.tera.as_ref().expect("ERROR: generate called without a context!?");
        let mut repo_bytes = 0;
        for (templ_path, out_path) in self.settings.outputs.history::<GitRepo>(Some(parsed_repo), None) {
            let templ_path = templ_path.to_str().expect(&format!("ERROR: a summary template path is invalid: {}", templ_path.display()));
            let out_path = out_path.to_str().expect(&format!("ERROR: a summary output path is invalid: {}", out_path.display()));
            let mut paged_ctx = ctx.clone();
            paged_ctx.remove("history");
            let pages = parsed_repo.history.chunks(self.settings.paginate_history());
            let page_count = pages.len();
            for (idx, page) in pages.enumerate() {
                let pagination = Pagination::new(
                    idx + 1,
                    page_count,
                    &out_path,
                );
                paged_ctx.insert("page", &pagination.with_relative_paths());
                paged_ctx.insert("history", &page);
                match tera.render(templ_path, &paged_ctx) {
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
        Ok(repo_bytes)
    }

    pub fn gen_commit(&self, ctx: &Context, parsed_repo: &GitRepo, repo_desc: &GitsySettingsRepo, _repo: &Repository) -> Result<usize, GitsyError> {
        let mut ctx = ctx.clone();
        let tera = self.tera.as_ref().expect("ERROR: generate called without a context!?");
        let mut repo_bytes = 0;
        for (_id, commit) in &parsed_repo.commits {
            size_check!(repo_desc, repo_bytes, self.total_bytes.load(Ordering::Relaxed), break);
            ctx
                .try_insert("commit", &commit)
                .expect("Failed to add commit to template engine.");
            for (templ_path, out_path) in self.settings.outputs.commit(Some(parsed_repo), Some(commit)) {
                let templ_path = templ_path.to_str().expect(&format!("ERROR: a summary template path is invalid: {}", templ_path.display()));
                let out_path = out_path.to_str().expect(&format!("ERROR: a summary output path is invalid: {}", out_path.display()));
                match tera.render(templ_path, &ctx) {
                    Ok(rendered) => {
                        repo_bytes += self
                            .write_rendered(&out_path, &rendered);
                    }
                    Err(x) => match x.kind {
                        _ => error!("ERROR: {:?}", x),
                    },
                }
            }
            ctx.remove("commit");
        }
        Ok(repo_bytes)
    }

    pub fn gen_branches(&self, ctx: &Context, parsed_repo: &GitRepo, _repo_desc: &GitsySettingsRepo, _repo: &Repository) -> Result<usize, GitsyError> {
        let tera = self.tera.as_ref().expect("ERROR: generate called without a context!?");
        let mut repo_bytes = 0;
        for (templ_path, out_path) in self.settings.outputs.branches::<GitRepo>(Some(parsed_repo), None) {
            let templ_path = templ_path.to_str().expect(&format!("ERROR: a summary template path is invalid: {}", templ_path.display()));
            let out_path = out_path.to_str().expect(&format!("ERROR: a summary output path is invalid: {}", out_path.display()));
            let mut paged_ctx = ctx.clone();
            paged_ctx.remove("branches");
            let pages = parsed_repo.branches.chunks(self.settings.paginate_branches());
            let page_count = pages.len();
            for (idx, page) in pages.enumerate() {
                let pagination = Pagination::new(
                    idx + 1,
                    page_count,
                    &out_path,
                );
                paged_ctx.insert("page", &pagination.with_relative_paths());
                paged_ctx.insert("branches", &page);
                match tera.render(templ_path, &paged_ctx) {
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
        Ok(repo_bytes)
    }

    pub fn gen_branch(&self, ctx: &Context, parsed_repo: &GitRepo, repo_desc: &GitsySettingsRepo, _repo: &Repository) -> Result<usize, GitsyError> {
        let mut ctx = ctx.clone();
        let tera = self.tera.as_ref().expect("ERROR: generate called without a context!?");
        let mut repo_bytes = 0;
        for branch in &parsed_repo.branches {
            size_check!(repo_desc, repo_bytes, self.total_bytes.load(Ordering::Relaxed), break);
            ctx.insert("branch", branch);
            for (templ_path, out_path) in self.settings.outputs.branch(Some(parsed_repo), Some(branch)) {
                let templ_path = templ_path.to_str().expect(&format!("ERROR: a summary template path is invalid: {}", templ_path.display()));
                let out_path = out_path.to_str().expect(&format!("ERROR: a summary output path is invalid: {}", out_path.display()));
                match tera.render(templ_path, &ctx) {
                    Ok(rendered) => {
                        repo_bytes += self
                            .write_rendered(&out_path, &rendered);
                    }
                    Err(x) => match x.kind {
                        _ => error!("ERROR: {:?}", x),
                    },
                }
            }
            ctx.remove("branch");
        }
        Ok(repo_bytes)
    }

    pub fn gen_tags(&self, ctx: &Context, parsed_repo: &GitRepo, _repo_desc: &GitsySettingsRepo, _repo: &Repository) -> Result<usize, GitsyError> {
        let tera = self.tera.as_ref().expect("ERROR: generate called without a context!?");
        let mut repo_bytes = 0;
        for (templ_path, out_path) in self.settings.outputs.tags::<GitRepo>(Some(parsed_repo), None) {
            let templ_path = templ_path.to_str().expect(&format!("ERROR: a summary template path is invalid: {}", templ_path.display()));
            let out_path = out_path.to_str().expect(&format!("ERROR: a summary output path is invalid: {}", out_path.display()));
            let mut paged_ctx = ctx.clone();
            paged_ctx.remove("tags");
            let pages = parsed_repo.tags.chunks(self.settings.paginate_tags());
            let page_count = pages.len();
            for (idx, page) in pages.enumerate() {
                let pagination =
                    Pagination::new(idx + 1, page_count, &out_path);
                paged_ctx.insert("page", &pagination.with_relative_paths());
                paged_ctx.insert("tags", &page);
                match tera.render(templ_path, &paged_ctx) {
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
        Ok(repo_bytes)
    }

    pub fn gen_tag(&self, ctx: &Context, parsed_repo: &GitRepo, repo_desc: &GitsySettingsRepo, _repo: &Repository) -> Result<usize, GitsyError> {
        let mut ctx = ctx.clone();
        let tera = self.tera.as_ref().expect("ERROR: generate called without a context!?");
        let mut repo_bytes = 0;
        for tag in &parsed_repo.tags {
            size_check!(repo_desc, repo_bytes, self.total_bytes.load(Ordering::Relaxed), break);
            ctx.insert("tag", tag);
            if let Some(tagged_id) = tag.tagged_id.as_ref() {
                if let Some(commit) = parsed_repo.commits.get(tagged_id) {
                    ctx.insert("commit", &commit);
                }
            }
            for (templ_path, out_path) in self.settings.outputs.tag(Some(parsed_repo), Some(tag)) {
                let templ_path = templ_path.to_str().expect(&format!("ERROR: a summary template path is invalid: {}", templ_path.display()));
                let out_path = out_path.to_str().expect(&format!("ERROR: a summary output path is invalid: {}", out_path.display()));
                match tera.render(templ_path, &ctx) {
                    Ok(rendered) => {
                        repo_bytes +=
                            self.write_rendered(&out_path, &rendered);
                    }
                    Err(x) => match x.kind {
                        _ => error!("ERROR: {:?}", x),
                    },
                }
            }
            ctx.remove("tag");
            ctx.remove("commit");
        }
        Ok(repo_bytes)
    }

    pub fn gen_files(&self, ctx: &Context, parsed_repo: &GitRepo, _repo_desc: &GitsySettingsRepo, _repo: &Repository) -> Result<usize, GitsyError> {
        let mut ctx = ctx.clone();
        let tera = self.tera.as_ref().expect("ERROR: generate called without a context!?");
        let mut repo_bytes = 0;
        for (templ_path, out_path) in self.settings.outputs.files::<GitRepo>(Some(parsed_repo), None) {
            let templ_path = templ_path.to_str().expect(&format!("ERROR: a summary template path is invalid: {}", templ_path.display()));
            let out_path = out_path.to_str().expect(&format!("ERROR: a summary output path is invalid: {}", out_path.display()));
            ctx.insert("root_files", &parsed_repo.root_files);
            ctx.insert("all_files", &parsed_repo.all_files);
            match tera.render(templ_path, &ctx) {
                Ok(rendered) => {
                    repo_bytes +=
                        self.write_rendered(&out_path, &rendered);
                }
                Err(x) => match x.kind {
                    _ => error!("ERROR: {:?}", x),
                },
            }
        }
        Ok(repo_bytes)
    }

    pub fn gen_file(&self, ctx: &Context, parsed_repo: &GitRepo, repo_desc: &GitsySettingsRepo, repo: &Repository) -> Result<usize, GitsyError> {
        let tera = self.tera.as_ref().expect("ERROR: generate called without a context!?");
        let mut repo_bytes = 0;

        #[cfg(any(feature = "highlight", feature = "highlight_fast"))]
        if self.settings.outputs.has_files() {
            let ts = ThemeSet::load_defaults();
            let theme = ts
                .themes
                .get(
                    repo_desc
                        .syntax_highlight_theme
                        .as_deref()
                        .unwrap_or("base16-ocean.dark"),
                )
                .expect("Invalid syntax highlighting theme specified.");
            let css: String = css_for_theme_with_class_style(theme, syntect::html::ClassStyle::Spaced)
                .expect("Invalid syntax highlighting theme specified.");
            repo_bytes +=
                self.write_rendered(&self.settings.outputs.syntax_css::<GitFile>(Some(&parsed_repo), None), css.as_str());
        }

        // TODO: parallelize the rest of the processing steps.  This one is
        // done first because syntax highlighting is very slow.
        let files: Vec<&GitFile> = parsed_repo.all_files.iter().filter(|x| x.kind == "file").collect();
        let atomic_bytes: AtomicUsize = AtomicUsize::new(repo_bytes);
        let repo_path = repo.path().to_str().expect("ERROR: unable to determine path to local repository");
        let _ = files
            .par_iter()
            .fold(
                || Some(0),
                |acc, file| {
                    // These two have to be recreated.  Cloning the Tera context is expensive.
                    let repo = Repository::open(&repo_path).expect("Unable to find git repository.");
                    let mut ctx = ctx.clone();

                    let mut local_bytes = 0;
                    let cur_repo_bytes = atomic_bytes.load(Ordering::Relaxed);
                    size_check!(repo_desc, cur_repo_bytes, self.total_bytes.load(Ordering::Relaxed), return None);
                    let file = match file.size < repo_desc.limit_file_size.unwrap_or(usize::MAX) {
                        true => GitsyGenerator::fill_file_contents(&repo, &file, &repo_desc)
                            .expect("Failed to parse file."),
                        false => (*file).clone(),
                    };
                    ctx
                        .try_insert("file", &file)
                        .expect("Failed to add file to template engine.");
                    for (templ_path, out_path) in self.settings.outputs.file(Some(parsed_repo), Some(&file)) {
                        let templ_path = templ_path.to_str().expect(&format!("ERROR: a summary template path is invalid: {}", templ_path.display()));
                        let out_path = out_path.to_str().expect(&format!("ERROR: a summary output path is invalid: {}", out_path.display()));
                        match tera.render(templ_path, &ctx) {
                            Ok(rendered) => {
                                local_bytes = self.write_rendered(&out_path, &rendered,);
                                atomic_bytes.fetch_add(local_bytes, Ordering::Relaxed);
                            }
                            Err(x) => match x.kind {
                                _ => error!("ERROR: {:?}", x),
                            },
                        }
                    }
                    ctx.remove("file");
                    Some(acc.unwrap() + local_bytes)
                },
            )
            .while_some() // allow short-circuiting if size limit is reached
            .sum::<usize>();
        repo_bytes = atomic_bytes.load(Ordering::Relaxed);
        Ok(repo_bytes)
    }

    pub fn gen_dir(&self, ctx: &Context, parsed_repo: &GitRepo, repo_desc: &GitsySettingsRepo, repo: &Repository) -> Result<usize, GitsyError> {
        let mut ctx = ctx.clone();
        let tera = self.tera.as_ref().expect("ERROR: generate called without a context!?");
        let mut repo_bytes = 0;
        for dir in parsed_repo.all_files.iter().filter(|x| x.kind == "dir") {
            size_check!(repo_desc, repo_bytes, self.total_bytes.load(Ordering::Relaxed), break);
            let listing = dir_listing(&repo, &dir).expect("Failed to parse file.");
            ctx.insert("dir", dir);
            ctx
                .try_insert("files", &listing)
                .expect("Failed to add dir to template engine.");
            for (templ_path, out_path) in self.settings.outputs.dir(Some(parsed_repo), Some(dir)) {
                let templ_path = templ_path.to_str().expect(&format!("ERROR: a summary template path is invalid: {}", templ_path.display()));
                let out_path = out_path.to_str().expect(&format!("ERROR: a summary output path is invalid: {}", out_path.display()));
                match tera.render(templ_path, &ctx) {
                    Ok(rendered) => {
                        repo_bytes +=
                            self.write_rendered(&out_path, &rendered);
                    }
                    Err(x) => match x.kind {
                        _ => error!("ERROR: {:?}", x),
                    },
                }
            }
            ctx.remove("files");
            ctx.remove("dir");
        }
        Ok(repo_bytes)
    }

    fn copy_assets(&self, repo_desc: Option<&GitsySettingsRepo>, parsed_repo: Option<&GitRepo>, repo: Option<&Repository>) -> Result<usize, GitsyError> {
        let mut bytes = 0;
        match repo_desc {
            Some(repo_desc) => {
                let parsed_repo = parsed_repo.expect("ERROR: attempted to fill repo assets without a repository");
                let repo = repo.expect("ERROR: attempted to fill repo assets without a repository");
                //let repo_path = repo.path().to_str().expect("ERROR: repository has no path!");
                if repo_desc.asset_files.is_some() {
                    let target_dir = self.settings.outputs.repo_assets::<GitFile>(Some(&parsed_repo), None);
                    for src_file in repo_desc.asset_files.as_ref().unwrap() {
                        let src_file = self.settings.outputs.asset(src_file, Some(parsed_repo), Some(repo));
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
                            bytes += meta.len() as usize;
                        }
                        loud!(" - copied asset: {}", src_file.display());
                    }
                }
            },
            _ => {
                if self.settings.asset_files.is_some() {
                    let target_dir = self.settings.outputs.global_assets::<GitFile>(None, None);
                    for src_file in self.settings.asset_files.as_ref().unwrap() {
                        let src_file = self.settings.outputs.asset(src_file, None, None);
                        let mut dst_file = PathBuf::from(&target_dir);
                        dst_file.push(
                            src_file
                                .file_name()
                                .expect(&format!("Failed to copy asset file: {}", src_file.display())),
                        );
                        std::fs::copy(&src_file, &dst_file)
                            .expect(&format!("Failed to copy asset file: {}", src_file.display()));
                        if let Ok(meta) = std::fs::metadata(dst_file) {
                            bytes += meta.len() as usize;
                        }
                        loud!(" - copied asset: {}", src_file.display());
                    }
                }
            },
        }
        Ok(bytes)
    }

    pub fn generate(&mut self) -> Result<(), GitsyError> {
        let start_all = Instant::now();
        self.tera = Some(self.tera_init()?);
        self.generated_dt = chrono::offset::Local::now();
        let mut total_bytes = 0;
        let mut repos: Vec<GitRepo> = vec![];

        if self.cli.should_clean {
            self.settings.outputs.clean();
        }

        if self.repo_descriptions.len() == 0 {
            panic!(
                "No Git repositories defined!  Please check your configuration file ({})",
                self.cli.path.display()
            );
        }

        self.settings.outputs.create();

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
            normal_noln!("[{}{}]... ", name, " ".repeat(longest_repo_name - name.len()));
            let repo_path = self.find_repo(&name, &repo_desc)?;
            let repo = Repository::open(&repo_path).expect("Unable to find git repository.");

            let metadata = GitsyMetadata {
                full_name: repo_desc.name.clone(),
                description: repo_desc.description.clone(),
                website: repo_desc.website.clone(),
                clone: repo_desc.clone_url.clone(),
                attributes: repo_desc.attributes.clone().unwrap_or_default(),
            };
            let parsed_repo = parse_repo(&repo, &name, &repo_desc, metadata).expect("Failed to analyze repo HEAD.");
            let minimized_repo = parsed_repo.minimal_clone(self.settings.limit_context.unwrap_or(usize::MAX));

            let mut local_ctx = self.new_context(Some(&minimized_repo))?;

            // Add README file to context, if specified and found
            if let Some(readmes) = &repo_desc.readme_files {
                for readme in readmes {
                    if let Some(file) = parsed_repo.root_files.iter().filter(|x| &x.name == readme).next() {
                        louder!(" - found readme file: {}", file.name);
                        let _ = GitsyGenerator::fill_file_contents(&repo, &file, &repo_desc)
                            .expect("Failed to parse file.");
                        local_ctx.insert("readme", &file);
                        break;
                    }
                }
            };

            repo_bytes += self.gen_summary( &local_ctx, &parsed_repo, repo_desc, &repo)?;
            repo_bytes += self.gen_branches(&local_ctx, &parsed_repo, repo_desc, &repo)?;
            repo_bytes += self.gen_branch(  &local_ctx, &parsed_repo, repo_desc, &repo)?;
            repo_bytes += self.gen_tags(    &local_ctx, &parsed_repo, repo_desc, &repo)?;
            repo_bytes += self.gen_tag(     &local_ctx, &parsed_repo, repo_desc, &repo)?;
            repo_bytes += self.gen_history( &local_ctx, &parsed_repo, repo_desc, &repo)?;
            repo_bytes += self.gen_commit(  &local_ctx, &parsed_repo, repo_desc, &repo)?;
            repo_bytes += self.gen_file(    &local_ctx, &parsed_repo, repo_desc, &repo)?;
            repo_bytes += self.gen_dir(     &local_ctx, &parsed_repo, repo_desc, &repo)?;
            repo_bytes += self.gen_files(   &local_ctx, &parsed_repo, repo_desc, &repo)?;

            self.copy_assets(Some(&repo_desc), Some(&parsed_repo), Some(&repo))?;

            repos.push(minimized_repo);
            normal!(
                "{}done in {:.2}s ({} bytes)",
                match VERBOSITY.load(Ordering::Relaxed) > 1 {
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
        let mut global_ctx = self.new_context(None)?;
        global_ctx.try_insert("repos", &repos)?;

        let mut global_bytes = 0;
        global_bytes += self.gen_repo_list(&global_ctx)?;
        global_bytes += self.gen_error(&global_ctx)?;

        self.copy_assets(None, None, None)?;

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

        if self.cli.should_open {
            if let Some((_templ, out)) = self.settings.outputs.repo_list::<GitFile>(None, None).first() {
                let _ = open::that(&format!("file://{}", out.display()));
            }
        }

        Ok(())
    }
}

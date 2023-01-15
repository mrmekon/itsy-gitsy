# Itsy-Gitsy
---
A static website generator for Git repositories.

## What

Itsy-Gitsy spiders across a collection of Git repositories, passes a subset of their contents through user-defined *input templates*, and generates a set of *output files*.  In standard usage, the input templates describe a website layout, and the output is a static website suitable for browsing locally, or hosting on a web server.

Since the output is always static text files, Itsy-Gitsy can generate more than just websites.  With custom templates, it can render your Git repositories as plain text, CSV, LaTeX, org-mode, Markdown, TOML, or whatever format you desire.

More generically, Itsy-Gitsy is a utility to generate text-based document trees from Git repositories based on descriptive templates.

## Why

The primary motivation is for self-hosting simple Git repository frontends without a dynamic web application.  For self-hosters, there can be many motivations for not wanting dynamically generated content, particularly resource, security, or maintenance requirements on the web server.  Most existing Git repository frontends are dynamic "forges" or "hubs", where even the lightweight ones are large, complex applications with significant resource requirements and large attack surfaces.

Side benefits include offline, local browsing without a web host, and generation of non-website content.  For instance, Itsy-Gitsy is also suitable for generating Git repositories as Gopher or Gemini sites, or even e-mail newsletters.

It is written in Rust and compiles in a single native executable, making it possible to (cross-)compile in a development environment, and run on a low-resource server with few dependencies.

## How

Behavior is dictated by a single TOML configuration file, which specifies the Git repositories to parse and various global and per-repository settings.  Itsy-Gitsy has a high degree of configurability, which allows for great flexibility of the output format.

Itsy-Gitsy uses [git2](https://github.com/rust-lang/git2-rs), which in turn uses [libgit2](https://libgit2.org/), to parse a list of local Git repositories into an internal representation.  Remote repositories available over non-authenticated HTTPS connections can also be specified, in which case they are cloned locally first.

The internal representation of repositories are passed through a configurable set of templates using the [Tera](https://tera.netlify.app/) template engine, which is itself based on the Jijna2 templating language.  After template substitution, the generated documents are written to user-configurable file paths.

If a file content template is provided, the contents of files stored in the repository can also be rendered.  These can optionally be rendered into HTML from Markdown with [pulldown-cmark](https://github.com/raphlinus/pulldown-cmark), and optionally be rendered as syntax highlighted HTML with [syntect](https://github.com/trishume/syntect).

Itsy-Gitsy currently only supports indexing a single branch for each repository.  The branch that is to be indexed is configurable.

## Project Status

Itsy-Gitsy is young and experimental.  It is under-tested and missing probably-important features.  Git supports extremely many combinations, and Itsy-Gitsy has only been tested with a tiny, tiny fraction of them.

The template "API" is not stable, and shouldn't be expected to be before a version 1.0.

Feedback, bug reports, and feature requests are welcome.

## Features

* Generate static, templated, multi-page output from Git repositories
* Index any number of Git repositories
* Configurable name, path, branch, description, website, etc.
* Site-wide and per-repository settings
* Multiple supported templates
  * List of all repositories
  * Summary of each repository
  * List of historical commits, branches, tags
  * Per-commit, per-tag, per-branch
  * Per file, with content
    * optional Markdown rendering
    * optional Syntax highlighting
  * Error page
* Configurable output
  * configurable file names
  * configurable directory structure
* Configurable limits for RAM and disk space usage
* Site-wide and per-repository asset files

## Getting Started

You can quickly try out Itsy-Gitsy by using the default configuration to render and open a locally browseable copy of a remote repository:

```bash
$ git clone https://github.com/mrmekon/itsy-gitsy
$ cd itsy-gitsy
$ cargo build --release
$ ./target/release/itsy-gitsy --clean --local --open --repo "https://github.com/mrmekon/itsy-gitsy"
```
\
Next, you will want to edit `config.toml` and point it to the Git repositories you want to index.  The default configuration file includes documentation to help you get started.

Now you can regenerate and view your repositories locally with:
```bash
$ ./target/release/itsy-gitsy --clean --local --open
```
\
If and when you are ready to move the site to a web server, regenerate it with:
```bash
$ rm -rf rendered/
$ ./target/release/itsy-gitsy --clean
```

## Command-line Arguments

| Argument    | Description                                                                                                                                                                                                                 |
|-------------|-----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `--config`  | Specifies the path to the TOML configuration file.  If none is specified, it will try to default to "config.toml" in the current directory.  A configuration file is mandatory, so Itsy-Gitsy will exit if it is not found. |
| `--clean`   | Whether to clean (remove) the output directory before generating.  It's a good idea to always specify this, to avoid stale files.                                                                                           |
| `--local`   | Whether to generate for browsing locally, i.e. with no web server and a a local `file:///path/to/dir` URL.  This temporarily removes the `site_url` setting, so it falls back to using local directories.                   |
| `--open`    | Whether to open the repository listing after generation.  This should typically be used with `--local`, and only works if the `repo_list` template is in use.                                                               |
| `--repo`    | Specify repositories to index from the command-line.  This overrides any repositories specified in the config file, and it can be specified several times.                                                                  |
| `--quiet`   | Suppresses all output to stdout, except for errors and warnings.                                                                                                                                                            |
| `--verbose` | Increases verbosity of output.  Can be specified up to four times.                                                                                                                                                          |


## Configuration

Itsy-Gitsy is configured via a single TOML configuration file.  By default, it looks for a file named `config.toml` in the working directory, but you can point it to another file with the `--config` command-line option.

See the included `config.toml` for full documentation of the available settings.

The top of the file contains global, site-wide settings like the site name, description, base URL, pagination rules, and memory limits.  Here you can also specify directories that contain Git repositories in subdirectories, which is used for bulk-import of many repositories.

This should be followed by the `[gitsy_templates]` section and `[gitsy_outputs]` sections, which define the input templates and output paths respectively.  Input templates that are not specified will not be generated, so you can disable any output types that you don't need by commenting out the appropriate line in `[gitsy_templates]`

An optional `[gitsy_extra]` section can be used to provide global, user-defined key/value pairs to all of the templates.  Use this if you want to add custom site-wide variables for use in your templates.

Finally, zero or more sections with arbitrary names define individual Git repositories to index.  Here, you can override most of the global settings at a per-repository level.  This is more powerful and allows specifying more metadata than bulk-import.

## Templates

Templates are defined using the [Tera](https://tera.netlify.app/) template engine.  Tera is a powerful templating language which allows variables, conditionals, loops, filtering, includes, hierarchical inheritance, and more.  Read its official documentation for details.

Itsy-Gitsy has a predetermined set of known template types, designed with a multi-page static Git browser in mind.  A default set of templates are provided, which demonstrate the generation of a full, multi-page Git repository browser.  You are very much encouraged to write your own, or modify the provided ones to suit your needs.

| Template       | Intended Usage                                   | Metadata                                             |
|----------------|--------------------------------------------------|------------------------------------------------------|
| `repo_list`    | Display a list of all indexed repositories.      | All metadata of all indexed repositories.            |
| `repo_summary` | Render a summary view of a single repository.    | All repo metadata (the current repo).                |
| `history`      | Render a list of historical commits.             | All repo metadata, optionally paginated on history.  |
| `commit`       | Render details and/or diff of a specific commit  | All repo metadata, plus a specific commit.           |
| `branches`     | Render a list of all branches in the repository. | All repo metadata, optionally paginated on branches. |
| `branch`       | Render details of a specific branch.             | All repo metadata, plus a specific branch.           |
| `tags`         | Render a list of all tags in the repository.     | All repo metadata, optionally paginated on tags.     |
| `tag`          | Render details of a specific tag.                | All repo metadata, plus a specific tag.              |
| `files`        | Render a list of all files in the repository.    | All repo metadata.                                   |
| `file`         | Render contents of a specific file.              | All repo metadata, plus a specific file.             |
| `dir`          | Render contents of a specific directory.         | All repo metadata, plus a specific directory.        |
| `error`        | Render a generic error page.                     | Only site-wide configuration.                        |

The templates absolutely do not need to be used for their "intended" purposes.  Modify their meaning to suit your needs!  You could, for instance, ignore the intended meaning of `repo_list` and instead use that template to generate an e-mail newsletter with the most recent 10 commits messages from all indexed repositories.

Any templates that are not specified in the configuration file are not evaluated, and their matching output files are not generated.  Use this to disable any features your site does not require.

### Filters

Tera templates support custom functions and filters, and Itsy-Gitsy defines a few for convenience:

| Name                | Type     | Purpose                                    | Example                                          |
|---------------------|----------|--------------------------------------------|--------------------------------------------------|
| only_files          | filter   | Filter the file tree into only files       | {{ all_files \| only_files }}                    |
| only_dirs           | filter   | Filter the file tree into only directories | {{ all_files \| only_dirs }}                     |
| hex                 | filter   | Output a number as a hex string            | {{ 17 \| hex }}                                  |
| oct                 | filter   | Output a number as an octal string         | {{ 17 \| oct }}                                  |
| mask                | filter   | Bitwise mask a number with another number  | {{ 17 \| mask(mask="0x77") }}                    |
| ts_to_date          | function | Convert a timestamp and offset to a date   | {{ts_to_date(ts=ts_utc, tz=ts_offset)}}          |
| ts_to_git_timestamp | function | Same, but print in standard Git format     | {{ts_to_git_timestamp(ts=ts_utc, tz=ts_offset)}} |

## Security

Security is, for the most part, outsourced to the libraries Itsy-Gitsy depends on.  [git2](https://github.com/rust-lang/git2-rs) handles the security of Git repo access, [Tera](https://tera.netlify.app/) and the templates files themselves handle sanitizing HTML outputs, [pulldown-cmark](https://github.com/raphlinus/pulldown-cmark) handles sanitizing Markdown output, and [syntect](https://github.com/trishume/syntect) handles sanitizing syntax highlighted file contents.  If any of these libraries contain security issues, then so does Itsy Gitsy.

The main thing Itsy-Gitsy itself is responsible for is ensuring it only writes files to its output directory.  It has some basic protections against obvious attempts to write outside of the output subdirectory, but nothing invinsible.

As always, if security is a concern, best practice is to follow the rules of least-privilege.  Run Itsy-Gitsy under a dedicated, low-privilege user account against Git repositories with read-only or no upstream access.  For maximum paranoia, disable syntax highlighting and Markdown rendering, and use filesystem namespaces to restrict it to read-only access of Git repositories and read-write access to the output directory.


## Performance

High performance is not a primary goal of Itsy-Gitsy, since it is primarily intended for indexing small personal projects, but various settings are provided to allow it to handle large repositories.

The majority of parsing and generation is linear and single-threaded, except for rendering file content output.  File contents are rendered in parallel, including syntax highlighting and Markdown rendering.

Syntax highlighting uses syntect's pure-Rust implementation by default, to avoid an extra dependency.  This implementation is quite slow, and performance can be greatly improved by using syntect's `onig` mode, which uses the faster Oniguruma C library for highlighting.  This can be enabled at build time with `cargo build --features highlight_fast`.

All metadata of all repositories, except for file contents, is held in memory.  Large repositories can easily exhaust memory, and disk usage can also get quite high.  There are several `limit_*` settings available in the configuration for restricting the amount of data held in memory, with the tradeoff of reducing the amount of data available for the generated output.  `limit_context` and `limit_diffs` are particularly important restrictions to set on repositories with thousands of commits.

Small repositories with dozens to hundreds of commits can be generated on the order of a few seconds or less.  Large repositories take *considerably* longer; parsing 1,000,000 commits from the Linux kernel repository with `limit_tree_depth = 3`, `limit_context = 10` and `limit_diffs = 100` took ~30 minutes on a fast laptop, and produced a ~2GB website.

## Limitations

* Only indexes history of one branch.
* No permalinks.  Links to file contents are invalidated if the file changes.
* High memory usage for large repositories.
* Limited to the pre-defined set of input templates.

## Main Dependencies

* [git2](https://github.com/rust-lang/git2-rs) -- Rust wrapper for libgit2 library.
* [libgit2](https://libgit2.org/) -- C library for accessing Git repositories.
* [Tera](https://tera.netlify.app/) -- Rust templating engine based on Jijna2.
* [pulldown-cmark](https://github.com/raphlinus/pulldown-cmark) -- Rust library for rendering Markdown to HTML.
* [syntect](https://github.com/trishume/syntect) -- Rust library for rendering file content into syntax highlighted HTML.
* [onig](https://github.com/rust-onig/rust-onig) (optional) -- Rust wrapper for Oniguruma syntax highlighting library.
* [oniguruma](https://github.com/kkos/oniguruma) (optional) -- C library for syntax highlighting.

## Similar Software

### Git Static Generators

I haven't used these, but they exist.  I'm sure they are good, too.  Itsy-Gitsy mostly differs in its configurability and focus on user-defined templates.

* [git-arr](https://blitiri.com.ar/p/git-arr/) -- Another Git static site generator, in Python.
* [stagit](https://codemadness.org/stagit.html) -- Another Git static site generator, in C.

### Git Forges

Forges typically include project management features, and particularly issue trackers.

* [Gitea](https://github.com/go-gitea/gitea) -- An open-source, self-hostable, dynamic forge.
* [Kallithea](https://kallithea-scm.org/repos/kallithea) -- An open-source, self-hostable, dynamic forge.
* [GitLab](https://about.gitlab.com/) -- An "open-core", self-hostable, dynamic forge.

### Git Browsers

* [gitweb](https://git-scm.com/book/en/v2/Git-on-the-Server-GitWeb) -- Git's built-in webserver plus dynamic repo browser.
* [cgit](https://git.zx2c4.com/cgit/about/) -- A dynamic repo browser.
* [shithub](https://only9fans.com/garden/shithub/HEAD/info.html) -- A hyper-minimalistic, open-source, self-hostable, dynamic repo browser.

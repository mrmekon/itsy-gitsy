# Itsy-Gitsy Changelog / News

## v0.5.0 -- 2023-01-29

* MAJOR: remove 1-to-1 template mapping restriction (config format changed)
* MAJOR: support parallel multi-thread/core execution
* rename "repo_summary" template to "summary"
* improve sanitization and verification of file paths
* add "%NAME%" filename template, allowing "permalinks"
* fix bugs in "limit_context" behavior
* improve detection of when limits are exceeded (particularly repo size limits)
* more "limit" settings that make multi-million commit repos parsable
* add "fetch_remote" setting, to disable fetch on remote repos

## v0.4.1 -- 2023-01-15

* add a "dark" theme for default site
* add sensible defaults to sample config
* add more documentations, examples
* change default main output names to "index.html"
* fix missing tags in "alt_refs" template variable

## v0.4.0 -- 2023-01-15

* MAJOR: include default templates for a full site
* MAJOR: add template type for individual files
* improved handling of file paths
* configurable branch names
* configurable limits
* repository "clone URL"
* "clean" build option
* "local" build option
* ability to sort repo list by date
* documentation

## v0.3.0 -- 2023-01-12

* MAJOR: paginated output for history, commits, and tags
* default paths: `clones_repos/` and `rendered/`

## v0.2.0 -- 2023-01-12 (first "release")

* MAJOR: initial release, basic git repo templated output

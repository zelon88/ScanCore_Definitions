# ScanCore Definitions

Threat definitions for [ScanCore](https://github.com/zelon88/ScanCore), built from
raw feeds by one script that runs the same way here as it does on a maintainer's
laptop.

    php Build/scancore-defs.php --all

## Components

Three PHP files, released together and checked against each other before any work
begins.

    Build/scancore-defs.php           the core logic, and where the version is declared
    Build/scancore-defs-version.php   the version manifest, an EXACT match
    Build/scancore-defs-config.php    paths and fetch settings, a MINIMUM match

The builder refuses to start unless both are present and both check out. A builder
running against the wrong half of a release produces a definition file that looks
correct and is not, which is worse than not running.

## How it fits together

    Recipes/     one file per source: where to fetch it, how to read it, what it may become
    Sources/     the raw download, committed exactly as it arrived
    Policy/      length limits & the allowlist of values that may never become indicators
    Build/       the three application files
    ScanCore_*.def   built output, committed, what ScanCore downloads
    Local/       built output from sources that may not be redistributed, never committed
    BUILD_REPORT.txt  everything the build refused, and why

Sources are committed raw so a build is reproducible from what is in the
repository, and so a feed that turns out to be publishing rubbish can be traced
after the fact rather than argued about.

## Licensing, and why Local exists

This repository is GPLv3. A threat feed is not. Those two facts do not merge just
because the data passed through a build script.

Every recipe declares a `license` and a `redistribute` field, and a recipe that
declares no license is skipped rather than guessed at. A source marked
`redistribute = yes` is built into the `ScanCore_*.def` files this repository
publishes. Anything else is built into `Local/`, which is gitignored.

abuse.ch data is a worked example. It is free under their fair use principles,
but their terms note that commercial or for-profit use may require a paid
subscription, and their exports now need an account Auth-Key. HRConvert2 is GPLv3
and is deployed commercially, so baking that data into a published artefact would
hand a downstream operator an obligation they never agreed to. The recipes are
included and work; they build to `Local/`. Fetch them at home with your own key.

## Running it

    php Build/scancore-defs.php --all

That fetches every enabled recipe, rebuilds the definition files and verifies them.
Add `--offline` to rebuild from what is already in `Sources/` without touching the
network, `--dry-run` to see what would happen, or `--recipe <name>` to work on one.

`--redistributable-only` skips any recipe marked `redistribute = no`, without even
fetching it. That is what the GitHub Action uses.

## The GitHub Action

The Action runs the same script. You do not need to run anything locally for it to
work, and running the script locally does not trigger it.

To run it by hand: **Actions** tab, **Build definitions**, **Run workflow**. Or
`gh workflow run build-definitions.yml`. Otherwise it runs weekly on Monday.

Three things that catch people out:

- The **Run workflow** button only appears once the workflow file is on the default
  branch. Same for the schedule. Commit it to `main` before looking for it.
- Opening a pull request needs more than the `permissions:` block in the workflow.
  Go to **Settings, Actions, General, Workflow permissions**, choose **Read and
  write permissions**, and tick **Allow GitHub Actions to create and approve pull
  requests**. GitHub turns that off by default on new personal repositories, and
  without it the run fails with `GitHub Actions is not permitted to create or
  approve pull requests`.
- GitHub disables scheduled workflows in a repository with no activity for 60 days.

Until a fetchable redistributable feed is wired up, the Action will rebuild an
identical `ScanCore_Virus.def` every week and open no pull request, because nothing
changed. That is correct behaviour, not a failure.

## A limit worth knowing before adding a large feed

A hash indicator costs nothing to add. It is one array lookup per file, whatever the
size of the set.

A `data`, `host` or `url` indicator is different. Each one is searched through every
byte of every file scanned, so the cost grows with the number of indicators times the
size of the data. Measured on a 240 MB corpus, 404 byte signatures added 8.6 seconds
to a 15.4 second scan. That is about 21 milliseconds per signature per 240 MB.

Extrapolated, a feed of 200,000 URLs would add roughly seventy minutes to that same
scan. URLhaus is that size. Do not enable a feed of that scale against the current
matcher without either capping how many string indicators are built, restricting them
to a file type with `scope=`, or replacing the per indicator search with a multi
pattern matcher. The `maxentries` limit in `Policy/limits.txt` is the blunt version of
that guard and defaults to 500,000, which is far too high for string indicators.

## Adding a source

Write a recipe. No code changes.

    url          = https://example.org/feed.csv
    file         = example-feed.csv
    format       = csv
    comment      = #
    skiplines    = 1
    kind         = sha256
    label        = Malware.ExampleFeed
    value        = column 2
    category     = Malware
    confidence   = medium
    license      = CC0, verified 2026-09-03
    redistribute = yes

`kind`, `label` and `value` each accept a literal or `column N`.

See `Documentation/DEFINITION_FORMAT.txt` for the definition grammar, and
`Documentation/SCANCORE_DEFINITIONS_CHANGELOG.txt` for what changed and why.

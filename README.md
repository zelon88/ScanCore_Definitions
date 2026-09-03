# ScanCore Definitions

Threat definitions for [ScanCore](https://github.com/zelon88/ScanCore), built from
raw feeds by one script that runs the same way here as it does on a maintainer's
laptop.

    php Build/scancore-defs.php --all

## How it fits together

    Recipes/     one file per source: where to fetch it, how to read it, what it may become
    Sources/     the raw download, committed exactly as it arrived
    Policy/      length limits & the allowlist of values that may never become indicators
    Build/       the one script
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

See `Documentation/DEFINITION_FORMAT.txt` for the definition grammar itself.

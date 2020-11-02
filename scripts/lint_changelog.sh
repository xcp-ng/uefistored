#!/bin/bash

# lint_changelog.sh - Check that CHANGELOG.md is valid.  Use as a pre-push hook.

# CHANGELOG update rules
#
# For the new version number tag, there must be:
#    1. A tag/version section with the corresponding date
#    2. A github.com diff link between previous version, linking [${tag}] to
#       the diff of the previous tag to the current tag

die() {
    echo "$@" >&2
    exit 1
}

lasttag=$(git tag --list --sort="taggerdate" | tail -n 1)
version=${lasttag#"v"}

if [[ "x$lasttag" = "x" ]];
then
    echo "No tags found, exit peacefully"
    exit 0
fi

tags=$(git tag)

if [[ ! "${tags}" =~ "${lasttag}" ]];
then
    die "Tag ${lasttag} not found"
fi


section=$(cat CHANGELOG.md | grep -E "\#\# \[${version}\] - [0-9]{4}-[0-9]{1,2}-[0-9]{1,2}")

if [[ "x${section}" == "x" ]];
then
    die "Must include section of changes for tag '${lasttag}' (version: $version)"
fi

compare=$(cat CHANGELOG.md | grep -E "\[${version}\]: https://github.com/.*/compare/v[0-9]{1,}.[0-9]{1,}.[0-9]{1,}\.\.\.v${version}")

if [[ "x${compare}" == "x" ]];
then
    die "Must include link to compare of changes for tag '${lasttag}' (version: $version)"
fi

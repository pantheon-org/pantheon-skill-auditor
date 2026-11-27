#!/usr/bin/env bash
#
# label-release-pr.sh
#
# Moves the merged release PR for the pushed tag from "autorelease: pending" to
# "autorelease: tagged". release-please does that relabel itself only when it
# creates the GitHub Release, and this repository leaves the release to cargo-dist
# (skip-github-release), so without this step the merged release PR stays pending
# and every later release-please run aborts with "There are untagged, merged
# release PRs outstanding".
# Kept by hand: tag-release.sh is rendered by pantheon-scaffold.
# Run by .github/workflows/release-label.yml on a version tag.
# Env: GH_TOKEN (issues and pull-requests write), GH_REPO (owner/name),
#      GITHUB_REF_NAME (the tag, vX.Y.Z)

set -euo pipefail

tag="${GITHUB_REF_NAME:?GITHUB_REF_NAME must name the tag}"
version="${tag#v}"
pending="autorelease: pending"
tagged="autorelease: tagged"

# The release PR is titled "chore(main): release X.Y.Z".
numbers=$(gh pr list --repo "$GH_REPO" --state merged --label "$pending" \
  --json number,title \
  --jq ".[] | select(.title | endswith(\"release $version\")) | .number")

if [ -z "$numbers" ]; then
  echo "No merged release PR labelled \"$pending\" for $tag. Nothing to do."
  exit 0
fi

# release-please creates this label when it relabels; create it if it is missing.
gh label create "$tagged" --repo "$GH_REPO" --color ededed \
  --description "release-please: the release PR's version is tagged" --force >/dev/null

for n in $numbers; do
  gh api --method POST "repos/$GH_REPO/issues/$n/labels" -f "labels[]=$tagged" >/dev/null
  gh api --method DELETE "repos/$GH_REPO/issues/$n/labels/autorelease:%20pending" >/dev/null
  echo "Labelled release PR #$n \"$tagged\" for $tag."
  echo "- Labelled release PR #$n \"$tagged\" for $tag." >> "${GITHUB_STEP_SUMMARY:-/dev/null}"
done

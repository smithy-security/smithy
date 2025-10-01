#!/bin/bash
set -xe
export ERL_FLAGS="-noinput -noshell"
export TERM="dumb"
export PATH=$PATH:$HOME/.mix/escripts

WORKSPACE=$1
RESULTS_DIR=$2

mkdir -p "$RESULTS_DIR"

# Step 1: Find all Phoenix/Elixir projects, don't include deps and build folders
projects=$(find "${WORKSPACE}" \
  -type f -name mix.exs \
  -not -path "*/deps/*" \
  -not -path "*/_build/*" \
  -exec dirname {} \;)

# Step 2: Run sobelow in each project and store separate SARIFs
i=0
for project in $projects; do
  # Remove the leading './' and convert '.' to an empty string
  project_path_clean="${project#./}"
  if [ "$project_path_clean" = "." ]; then
    project_path_clean=""
  fi

  outfile="${RESULTS_DIR}/sobelow_${i}.sarif.json"
  echo "Scanning $project -> $outfile"

  (cd "$project" && sobelow --format sarif 2>/dev/null | \
    jq -s 'first(.[]) | .runs[0].results |= map(
      .locations |= map(
        .physicalLocation.artifactLocation.uri = (
          if "'"${project_path_clean}"'" == "" then
            .physicalLocation.artifactLocation.uri
          else
            "'"${project_path_clean}"'" + "/" + .physicalLocation.artifactLocation.uri
          end
        )
      )
    )' \
  ) > "$outfile" || true

  i=$((i+1))
done
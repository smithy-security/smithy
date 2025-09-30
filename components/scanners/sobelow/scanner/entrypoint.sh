#!/bin/bash
set -xe
export ERL_FLAGS="-noinput -noshell"
export TERM="dumb"
export PATH=$PATH:$HOME/.mix/escripts

WORKSPACE=$1
FINAL_OUT=$2
OUT_DIR=$(dirname "$FINAL_OUT")
TMP_DIR=$(mktemp -d "$OUT_DIR/tmp.XXXXXX")

# Step 1: Find all Phoenix/Elixir projects, don't include deps and build folders
projects=$(find "$WORKSPACE" \
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

  outfile="$TMP_DIR/sobelow_${i}.sarif.json"
  echo "Scanning $project -> $outfile"

  (cd "$project" && sobelow --format sarif 2>/dev/null | \
    jq -s 'first(.[]) | .runs[0].results |= map(
      .locations |= map(
        .physicalLocation.artifactLocation.uri = (
          if "'"$project_path_clean"'" == "" then
            .physicalLocation.artifactLocation.uri
          else
            "'"$project_path_clean"'" + "/" + .physicalLocation.artifactLocation.uri
          end
        )
      )
    )' \
  ) > "$outfile" || true

  i=$((i+1))
done

# Step 3: Merge the individual SARIF files into one report
# Check if any SARIF files were created before attempting to merge
shopt -s nullglob
sarif_files=("$TMP_DIR"/sobelow_*.sarif.json)
shopt -u nullglob

if [ ${#sarif_files[@]} -gt 0 ]; then
  jq -s '
    {
      version: "2.1.0",
      "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
      runs: (map(.runs) | add)
    }
  ' "${sarif_files[@]}" > "$FINAL_OUT"

  # Clean up temporary directory
  rm -r "$TMP_DIR"
fi
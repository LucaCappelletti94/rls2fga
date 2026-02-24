#!/usr/bin/env bash
set -euo pipefail

if [[ $# -ne 1 ]]; then
  echo "commit-msg requires exactly one path argument." >&2
  exit 2
fi

path="$1"
if ! raw="$(cat "$path" 2>/dev/null)"; then
  echo "Failed to read commit message file $path" >&2
  exit 1
fi

subject=""
while IFS= read -r line; do
  trimmed="${line#"${line%%[![:space:]]*}"}"
  trimmed="${trimmed%"${trimmed##*[![:space:]]}"}"
  if [[ -z "$trimmed" || "$trimmed" == \#* ]]; then
    continue
  fi
  subject="$trimmed"
  break
done <<< "$raw"

if [[ -z "$subject" ]]; then
  echo "Commit message subject is empty." >&2
  exit 1
fi

for prefix in "Merge " "Revert \"" "fixup! " "squash! "; do
  if [[ "$subject" == "$prefix"* ]]; then
    exit 0
  fi
done

if ((${#subject} > 72)); then
  echo "Commit subject is ${#subject} chars (max 72): \`$subject\`" >&2
  exit 1
fi

if [[ "$subject" == *. ]]; then
  echo "Commit subject must not end with a period." >&2
  exit 1
fi

if [[ "$subject" != *": "* ]]; then
  echo "Commit subject must follow Conventional Commits, e.g. \`feat(parser): add xyz\`." >&2
  exit 1
fi

header="${subject%%: *}"
description="${subject#*: }"
if [[ -z "${description//[[:space:]]/}" ]]; then
  echo "Commit description after \`: \` must not be empty." >&2
  exit 1
fi

header="${header%!}"

if [[ "$header" == *"("* || "$header" == *")"* ]]; then
  if [[ "$header" != *"("* ]]; then
    echo "Invalid Conventional Commit header: unclosed scope parenthesis." >&2
    exit 1
  fi
  commit_type="${header%%(*}"
  scope_part="${header#*(}"
  if [[ "$scope_part" != *")" || -n "${scope_part#*)}" ]]; then
    echo "Invalid Conventional Commit header: unclosed scope parenthesis." >&2
    exit 1
  fi
else
  commit_type="$header"
fi

allowed_types=(build chore ci docs feat fix perf refactor revert style test)
is_allowed=0
for t in "${allowed_types[@]}"; do
  if [[ "$commit_type" == "$t" ]]; then
    is_allowed=1
    break
  fi
done

if [[ "$is_allowed" -eq 0 ]]; then
  echo "Invalid Conventional Commit type \`$commit_type\`. Allowed: ${allowed_types[*]}" >&2
  exit 1
fi

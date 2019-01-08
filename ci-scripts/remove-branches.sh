#!/bin/bash

git fetch --prune &> /dev/null
branches=$(git branch -r | grep -v "origin/master" | awk -F/ '{print $NF}')
if [ -z "$branches" ]; then
  echo "No branches need to be removed"
else
  # shellcheck disable=SC2086
  git push origin --delete $branches 2> /dev/null
fi

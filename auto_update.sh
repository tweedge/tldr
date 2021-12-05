#!/bin/bash
# toss the old scan
rm -rf archives

# download all-new data
python3 scan.py

# prep for GitHub update, reducing unneeded deltas
sort -o ZONES.md ZONES.md

# push the update
git add -A .
git commit -m "Updating zone information"
git push
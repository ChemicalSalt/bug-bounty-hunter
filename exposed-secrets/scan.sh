#!/bin/bash
# Scan public GitHub repos for exposed secrets
subfinder -dL domains.txt -silent -o exposed-secrets/subs.txt
trufflehog github --org=$(cat domains.txt) --json > exposed-secrets/results.txt

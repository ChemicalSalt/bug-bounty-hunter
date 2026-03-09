#!/bin/bash
# Check for exposed .env, .git, backup files
subfinder -dL domains.txt -silent -o exposed-files/subs.txt
nuclei -l exposed-files/subs.txt -t exposures -o exposed-files/results.txt

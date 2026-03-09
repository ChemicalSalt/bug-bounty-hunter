#!/bin/bash
# Check for open/misconfigured S3 buckets
subfinder -dL domains.txt -silent -o s3-buckets/subs.txt
nuclei -l s3-buckets/subs.txt -t misconfiguration/aws -o s3-buckets/results.txt

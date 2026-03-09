#!/bin/bash
subfinder -dL domains.txt -silent -o subdomain-takeover/subs.txt
httpx -l subdomain-takeover/subs.txt -cname -status-code -mc 404 -o subdomain-takeover/cname_404.txt
nuclei -l subdomain-takeover/subs.txt -t takeovers -o subdomain-takeover/results.txt

# vah-URLFuzzer

Performs basic URL fuzzing against a given URL to identify common files and directories (for example admin panels or backup files). It sends one GET request for each non-blank wordlist path, after a baseline probe of a random nonexistent path. A path is reported as found only when its response status is below 400 and its status and body size differ from the baseline response, so a catch-all server that answers every path the same way does not produce invented finds. It includes rate limiting, an optional output file for found URLs, and non-zero exit codes when the URL is invalid, the wordlist cannot be read, or every request fails.

## Install
`git clone https://github.com/ShadowGuard-AI/vah-urlfuzzer`

## Usage
`python main.py http://example.com -w common.txt`

## Parameters
- `-h`: Show help message and exit
- `-w`: Path to the wordlist file (default: common.txt)
- `-r`: Rate limit in seconds between requests (default: 0.5)
- `-t`: Request timeout in seconds (default: 10)
- `-o`: Output file to save found URLs
- `--no-status-codes`: Do not print HTTP status codes.

## License
Copyright (c) ShadowGuard-AI

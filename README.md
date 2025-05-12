# vah-URLFuzzer
Performs basic URL fuzzing against a given URL to identify common files and directories (e.g., .env, backup files, admin panels). Uses `requests` and a wordlist for common paths. Includes rate limiting to avoid overloading the target. - Focused on Automates tasks related to vulnerability assessment. Scrapes security advisories from specified websites, correlates vulnerabilities with installed software versions (determined through system information collection), and generates prioritized remediation recommendations.  Does NOT replace a full VA tool, but augments existing processes.

## Install
`git clone https://github.com/ShadowStrikeHQ/vah-urlfuzzer`

## Usage
`./vah-urlfuzzer [params]`

## Parameters
- `-h`: Show help message and exit
- `-w`: No description provided
- `-r`: No description provided
- `-t`: No description provided
- `-o`: Output file to save found URLs
- `--no-status-codes`: Do not print HTTP status codes.

## License
Copyright (c) ShadowStrikeHQ

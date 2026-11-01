import argparse
import requests
import logging
import time
import os
import sys
import uuid
from urllib.parse import urlparse

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

# Default wordlist file
DEFAULT_WORDLIST = "common.txt"  # You should provide a 'common.txt' file

def setup_argparse():
    """
    Sets up the argument parser for the URL fuzzer.
    """
    parser = argparse.ArgumentParser(description="vah-URLFuzzer: Performs basic URL fuzzing.")
    parser.add_argument("url", help="The URL to fuzz (e.g., http://example.com)")
    parser.add_argument("-w", "--wordlist", default=DEFAULT_WORDLIST, help="Path to the wordlist file (default: common.txt)")
    parser.add_argument("-r", "--rate_limit", type=float, default=0.5, help="Rate limit in seconds between requests (default: 0.5)")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="Request timeout in seconds (default: 10)")
    parser.add_argument("-o", "--output", help="Output file to save found URLs", type=str)
    parser.add_argument("--no-status-codes", action="store_true", help="Do not print HTTP status codes.") # added
    return parser.parse_args()


def validate_url(url):
    """
    Validates the URL format.
    """
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except:
        return False


def fuzz_url(url, wordlist_file, rate_limit, timeout, output_file, no_status_codes):
    """Fuzz paths. Returns 0 if at least one request completed, 1 otherwise."""
    try:
        with open(wordlist_file, "r") as f:
            paths = [line.strip() for line in f if line.strip()]
    except FileNotFoundError:
        logging.error(f"Wordlist file not found: {wordlist_file}")
        return 1
    except Exception as e:
        logging.error(f"Error reading wordlist file: {e}")
        return 1
    if not paths:
        logging.error("Wordlist contains no usable entries.")
        return 1
    baseline_status = None
    baseline_len = None
    baseline_path = f"nonexistent-{uuid.uuid4().hex[:16]}"
    try:
        b = requests.get(f"{url.rstrip('/')}/{baseline_path}", timeout=timeout)
        baseline_status, baseline_len = b.status_code, len(b.content)
        if baseline_status < 400:
            logging.warning(f"Catch-all baseline: random path returned status {baseline_status} with {baseline_len} bytes; responses matching that status and size will not be reported as found.")
    except requests.exceptions.RequestException as e:
        logging.error(f"Baseline probe failed: {e}")
    found_urls = []
    completed = 0
    for path in paths:
        fuzzed_url = f"{url.rstrip('/')}/{path.lstrip('/')}"
        try:
            response = requests.get(fuzzed_url, timeout=timeout)
            completed += 1
            is_baseline_match = (baseline_status is not None and response.status_code == baseline_status and len(response.content) == baseline_len)
            if response.status_code < 400 and not is_baseline_match:
                logging.info(f"Found: {fuzzed_url}")
                found_urls.append(fuzzed_url)
                if not no_status_codes:
                    logging.info(f"Status Code: {response.status_code}")
            elif response.status_code != 404:
                if not no_status_codes:
                    logging.info(f"{fuzzed_url} - Status Code: {response.status_code}")
        except requests.exceptions.RequestException as e:
            logging.error(f"Error accessing {fuzzed_url}: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")
        time.sleep(rate_limit)
    if completed == 0:
        logging.error("All requests failed; no fuzzing was completed.")
        return 1
    if output_file:
        try:
            with open(output_file, "w") as outfile:
                for found_url in found_urls:
                    outfile.write(found_url + "\n")
            logging.info(f"Found URLs saved to: {output_file}")
        except Exception as e:
            logging.error(f"Error writing to output file: {e}")
            return 1
    return 0

def main():
    args = setup_argparse()
    if not validate_url(args.url):
        logging.error("Invalid URL format.  Please use a URL including scheme (http/https) and netloc (e.g., http://example.com).")
        return 1
    if not os.path.isfile(args.wordlist):
        logging.error(f"Wordlist file not found: {args.wordlist}")
        return 1
    if args.rate_limit < 0:
        logging.error("Rate limit must be a non-negative number.")
        return 1
    logging.info(f"Starting URL fuzzing against: {args.url}")
    status = fuzz_url(args.url, args.wordlist, args.rate_limit, args.timeout, args.output, args.no_status_codes)
    if status != 0:
        return status
    logging.info("URL fuzzing completed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

# Example Usage:
# 1. Basic fuzzing: python vah_URLFuzzer.py http://example.com
# 2. Using a custom wordlist: python vah_URLFuzzer.py http://example.com -w my_wordlist.txt
# 3. Adjusting the rate limit: python vah_URLFuzzer.py http://example.com -r 1.0
# 4. Saving found URLs to a file: python vah_URLFuzzer.py http://example.com -o found.txt
# 5. Adjusting timeout: python vah_URLFuzzer.py http://example.com -t 5
# 6. Suppress status code printing: python vah_URLFuzzer.py http://example.com --no-status-codes
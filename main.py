import argparse
import requests
import logging
import time
import os
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
    """
    Performs URL fuzzing using a wordlist.
    """
    try:
        with open(wordlist_file, "r") as f:
            # Blank lines survive this as empty strings, and an empty path joins into a request for the base URL itself. A wordlist with a trailing newline, which is most of them, spends one request rechecking the root and usually records it as a find.
            paths = [line.strip() for line in f]
    except FileNotFoundError:
        logging.error(f"Wordlist file not found: {wordlist_file}")
        return
    except Exception as e:
        logging.error(f"Error reading wordlist file: {e}")
        return

    found_urls = []

    for path in paths:
        fuzzed_url = f"{url.rstrip('/')}/{path.lstrip('/')}"  # Ensure no double slashes
        try:
            response = requests.get(fuzzed_url, timeout=timeout)
            # Below 400 is my whole definition of found, and requests has already followed any redirects before I see the code, so I am judging the final landing page, not the path I asked for. A soft 404 served with a 200 is a find in my book, and there is no content check anywhere that could overrule it.
            if response.status_code < 400: # Consider all codes below 400 as valid
                logging.info(f"Found: {fuzzed_url}")
                found_urls.append(fuzzed_url)
                if not no_status_codes:
                   logging.info(f"Status Code: {response.status_code}")


            # A 404 is dropped in complete silence while every other error at least earns a log line. Neither kind reaches the output file: only the found list is written below, so the saved result cannot show what was tried and rejected.
            elif response.status_code != 404:
                if not no_status_codes:
                    logging.info(f"{fuzzed_url} - Status Code: {response.status_code}")

        except requests.exceptions.RequestException as e:
            logging.error(f"Error accessing {fuzzed_url}: {e}")
        except Exception as e:
            logging.error(f"An unexpected error occurred: {e}")

        # The sleep runs after every word, including the last one and including words whose request just failed. A long wordlist against a dead host pays the full rate limit on top of every timeout.
        time.sleep(rate_limit)  # Rate limiting

    if output_file:
        try:
            with open(output_file, "w") as outfile:
                for found_url in found_urls:
                    outfile.write(found_url + "\n")
            logging.info(f"Found URLs saved to: {output_file}")
        except Exception as e:
            logging.error(f"Error writing to output file: {e}")

def main():
    """
    Main function to execute the URL fuzzer.
    """
    args = setup_argparse()

    if not validate_url(args.url):
        # Every validation failure in main returns without an exit code, here and on the wordlist and rate limit checks below. The process reports failure in the log and success to the shell, so a scripted run cannot tell a refused run from a completed one.
        logging.error("Invalid URL format.  Please use a URL including scheme (http/https) and netloc (e.g., http://example.com).")
        return

    if not os.path.isfile(args.wordlist):
        logging.error(f"Wordlist file not found: {args.wordlist}")
        return

    if args.rate_limit < 0:
        logging.error("Rate limit must be a non-negative number.")
        return

    logging.info(f"Starting URL fuzzing against: {args.url}")
    fuzz_url(args.url, args.wordlist, args.rate_limit, args.timeout, args.output, args.no_status_codes)
    logging.info("URL fuzzing completed.")


if __name__ == "__main__":
    main()

# Example Usage:
# 1. Basic fuzzing: python vah_URLFuzzer.py http://example.com
# 2. Using a custom wordlist: python vah_URLFuzzer.py http://example.com -w my_wordlist.txt
# 3. Adjusting the rate limit: python vah_URLFuzzer.py http://example.com -r 1.0
# 4. Saving found URLs to a file: python vah_URLFuzzer.py http://example.com -o found.txt
# 5. Adjusting timeout: python vah_URLFuzzer.py http://example.com -t 5
# 6. Suppress status code printing: python vah_URLFuzzer.py http://example.com --no-status-codes
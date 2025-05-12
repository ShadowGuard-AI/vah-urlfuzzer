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
            if response.status_code < 400: # Consider all codes below 400 as valid
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
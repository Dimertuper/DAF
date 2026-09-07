# Shodan Annotator

This module provides annotation functionality using the Shodan API. It first checks whether data is available for a given IP address using Shodan's InternetDB API, which has less strict rate limits and is suitable for high-volume queries. If relevant data is found, the module then retrieves detailed information from the main Shodan API, which may include operating system details of connected devices.

## Parameters

- `shodan_api_key_file` (str): Path to the file containing the Shodan API key.
- `shodan_api_url` (str): Base URL for the Shodan API (default: `https://api.shodan.io/shodan/host/`).
- `shodan_idb_url` (str): Base URL for the Shodan InternetDB API (default: `https://internetdb.shodan.io/`).
- `http_request_timeout` (int): Timeout for HTTP requests in seconds (default: `5`).
- `max_timeouts` (int): Maximum number of allowed HTTP request timeouts before aborting (default: `5`).
- `base_wait_time` (int): Base wait time in seconds between retries (default: `10`).

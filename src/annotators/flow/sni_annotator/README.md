# SNI Annotator

This module leverages OS-specific domains and URI paths used for updates or other system behaviors. It extracts `(URL, URI)` pairs from flow data and matches them against a database of known URL/URI-to-OS mappings. If a match is found, the module assigns annotation. Database is hancrafted.

## Parameters

- `db_file` (`str`): Path to the SNI database CSV file.
- `fields` (`list`): List of field names or `[url_field, uri_field]` pairs used for extraction.  
  Example: `["string TLS_SNI", ["string HTTP_REQUEST_HOST", "string HTTP_REQUEST_URL"]]`

## Database Format

The CSV file must have no header and contain three columns:

| Name       | Description                                 |
|------------|---------------------------------------------|
| url        | Hostname (SNI) used as the matching key     |
| uri        | Required URI path prefix or `*` wildcard    |
| os_family  | Operating system string (e.g., `windows`)   |

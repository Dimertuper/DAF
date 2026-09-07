# Hostname Annotator

The Hostname Annotator uses reverse DNS lookups to obtain the hostname of a device, which is then compared against its database. To function correctly, hostname annotation patterns must be defined in the following CSV files: `full-math.csv`, `sequences.csv`, and `subsequences.csv`. Each file requires a specific format, described below.

## Parameters

- `full_db` (str): Path to the database file.
- `sequences_db` (str): Name of the field containing MAC addresses to annotate.
- `subsequences_db` (str): Name of the field containing MAC addresses to annotate.

## Database Format

Each database is a CSV file with the following columns:

### `full-math.csv`

| Column      | Description                                                                                      |
|-------------|--------------------------------------------------------------------------------------------------|
| hostname    | Fully qualified hostname for reverse DNS lookups. Used for exact match annotation.               |
| group       | Device group annotation.                                                                         |
| class       | Device class annotation.                                                                         |
| os-family   | OS family annotation.                                                                            |
| os-type     | OS type annotation.                                                                              |
| os-version  | OS version annotation.                                                                           |

### `sequences.csv`

| Column      | Description                                                                                      |
|-------------|--------------------------------------------------------------------------------------------------|
| sequence    | Sequence string. Annotates if there is an exact match between two dots in a reverse DNS lookup.<br>Example: The sequence `printer` matches `xxx.printer.xxx.com`. |
| group       | Device group annotation.                                                                         |
| class       | Device class annotation.                                                                         |
| os-family   | OS family annotation.                                                                            |
| os-type     | OS type annotation.                                                                              |
| os-version  | OS version annotation.                                                                           |

### `subsequences.csv`

| Column      | Description                                                                                      |
|-------------|--------------------------------------------------------------------------------------------------|
| subsequence | Subsequence string. Annotates if the first sequence in a reverse DNS lookup contains the subsequence.<br>Examples: `client` matches `client-12335.xxx.xxx.com`; `windows` matches `mr-smith-windows.xxx.xxx.com`. |
| group       | Device group annotation.                                                                         |
| class       | Device class annotation.                                                                         |
| os-family   | OS family annotation.                                                                            |
| os-type     | OS type annotation.                                                                              |
| os-version  | OS version annotation.                                                                           |

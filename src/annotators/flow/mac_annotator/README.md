# MAC Annotator

This module provides annotation functionality using MAC address OUIs.  
It uses a modified MAC OUI database from [MAC Address Lookup](https://maclookup.app/downloads/json-database).

## Parameters

- `db_file` (`str`): Path to the database file.
- `src_mac_field` (`str`): Name of the field containing source MAC addresses to annotate.
- `dst_mac_field` (`str`): Name of the field containing destination MAC addresses to annotate.

## Database Format

The database must be a CSV file with the following columns:

| CSV Column Name | Description                |
|-----------------|---------------------------|
| macPrefix       | MAC address prefix (OUI)  |
| vendor          | Device vendor name        |
| OS_family       | OS family annotation      |

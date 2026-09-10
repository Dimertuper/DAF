# MAC Annotator

**Module:** `MACAnnotator` in `mac_annotator.py`, a flow-based annotator (`FlowAnnotator`). It reads MAC addresses from the flows and in windowed processing runs in every window. An IP with more than one MAC address is flagged as a multi-device.

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

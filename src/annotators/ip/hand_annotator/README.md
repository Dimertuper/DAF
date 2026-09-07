# Hand Annotator

The Hand Annotator is enabled by default in DAF. To function correctly, hand annotations must be specified in a file named `hand_annotation_rules.csv` using the format described below.

## Parameters

- **`db`** (`str`): Path to the database file containing the annotation rules.

## Database Format

The database should be a CSV file with the following columns:

| CSV Column Field Name | Description |
|----------------------|-------------|
| `ip_address`         | Identifies the object to be annotated. Supported formats: `<IPv4 address>` (e.g., `192.168.1.1`), `octet.octet.octet.{<octet>-<octet>}` (e.g., `192.168.1.{10-20}` for a range), and `<IPv4 address>/<mask>` (e.g., `192.168.1.0/24` for a network). IPv6 addresses are not supported. |
| `group`              | Annotation for the device group. |
| `class`              | Annotation for the device class. |
| `os-family`          | Annotation for the device OS family. |
| `os-type`            | Annotation for the device OS type. |
| `os-version`         | Annotation for the device OS version. |

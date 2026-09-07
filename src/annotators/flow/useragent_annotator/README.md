# HTTP User-Agent Annotator

This module extracts and analyzes HTTP User-Agent strings from flow records to infer OS and application metadata. It uses known signature databases derived from the WhatIsMyBrowser database.

## Parameters

- `field` (`str`): Field in the flow records containing the User-Agent string. Example: `"string HTTP_REQUEST_AGENT"`
- `keywords_db` (`str`): Path to the OS keyword database.
- `browsers_db` (`str`): Path to the browser user-agent regex database.
- `others_db` (`str`): Path to the non-browser user-agent regex database.
- `full_search` (`bool`): Set to `True` if incomplete user-agent strings are expected (enables more exhaustive matching).
- `mine_flag` (`bool`): Set to `True` to use the `mine_os` module, which uses simplified keywords.

## Components

### `translate_useragent.py`
Module translates a single HTTP User-Agent string into OS and application tags.

### `prepare_csv_table.py`
Processes a WhatIsMyBrowser CSV export and prepares regex-compatible tables for the translation module.

### `mine_os.py`
Detects the operating system by analyzing keywords extracted from the User-Agent string.

### `crate_placeholder.py`
Creates simplified, version-less "placeholder" forms of User-Agent strings to enable more consistent matching and aggregation.



## Helper modules

### Translate HTTP useragent module

Translate given HTTP useragent (input in cmd) in tags.

First, HTTP useragent is analyzed, if belongs to browser or not. If belong to browser, then module will work with csv table from parameter `-b --browsers`. Else with csv table from `-o --others`.

If useragent won't be found in CSV table, then will be added to JSON file for HUMAN LEARGING. (in development)

#### Parameters

- `-b --browsers <filename.suffix>` CSV table contains database of HTTP useragent for browsers.
- `-o --others <filename.suffix>` CSV table contains database of HTTP useragent for every other aplication.

#### Output

On cmd will be printed the founded tags (+ development information like time, matched regex, ...)

```
Input HTTP useragent:

Mozilla/5.0 (Linux; Android 7.0; Lenovo TB-8304F1) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.93 Safari/537.36

##################################################################################
re: Mozilla/[.0123456789\s]*\(Linux.*;\sAndroid.*;\sLenovo.*\)\s*AppleWebKit/[.0123456789\s]*\(KHTML, like Gecko\)\s*Chrome/[.0123456789\s]*Safari/[.0123456789\s]*
0.046347618103027344
Tags:
 user_agent: Mozilla/5.0 (Linux; Android 4.4.2; Lenovo A7600-F Build/KOT49H) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/44.0.2403.133 Safari/537.36
 simple_operating_platform_string: Lenovo
 software_name: Chrome
 operating_system: Android (KitKat)
 software_type: browser
 software_sub_type: web-browser
 hardware_type: mobile
```

### Prepare CSV table module

Module prepare `whatismybrowser.com` csv table for module `translate_useragent.py`.

CSV table will be splited to two parts. First `browsers_useragents.csv` contains HTTP useragents taht belongs to browsers. Seconde `others_useragents.csv` contains HTTP useragents for every other applications. In both tables are safed useragents in regex format, that allow Translate HTTP useragents module to not translate HTTP useragent to regex format. Only find respondents regex in csv table. And also allow better unique record handling.

Module also allows to add some new data to tables. Becouse the name and number of columns are not expected to match. The user is first able to use cmd to determine which column from the added table belongs to the columns from table where they will be stored.

#### Parameters

- `-f --file <filename.suffix>` CSV table contains database of HTTP useragent from `whatismybrowser.com`.
- `-o --others <path to folder>` Path to folder where will be safed output csv tables.
- `-a --add <filename.suffix>` CSV table contains database of HTTP useragent, taht need to be added to csv table from parameter -f

There are two possible combination of parameters:

- `-f` + `-o` For first preparation. In -f msut be file from `whatismybrowser.com`. In -o will be folder where will be safed csv tables `browsers_useragents.csv` and `others_useragents.csv`.
- `-f` + `-a` For adding some HTTP useragents to -f file. In -f can be `browsers_useragents.csv` or `others_useragents.csv`. In -a cab be file taht contains both of useragents (browsers and others). Module recognize with of them give to -f table.

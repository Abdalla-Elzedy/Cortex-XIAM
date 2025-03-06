# XQL & Cortex Data Model Reference Guide

![XQL Banner](https://img.shields.io/badge/XQL-Reference%20Guide-blue)
![Cortex XSIAM](https://img.shields.io/badge/Cortex-XSIAM-red)
![Version](https://img.shields.io/badge/Version-1.0-green)
![Last Updated](https://img.shields.io/badge/Last%20Updated-March%202025-lightgrey)

A comprehensive reference guide for XQL (XSIAM Query Language) and the Cortex Data Model (XDM) used in Palo Alto Networks' Cortex XSIAM platform.

## Table of Contents

- [Introduction](#introduction)
- [Basic Concepts](#basic-concepts)
  - [Dataset Selection](#dataset-selection)
  - [Basic Search](#basic-search)
  - [Filtering Data](#filtering-data)
- [Field Operations](#field-operations)
  - [Fields Selection](#fields-selection)
  - [Field Transformation](#field-transformation)
- [Data Joining & Combining](#data-joining--combining)
  - [Joins](#joins)
  - [Unions](#unions)
- [Aggregation & Statistics](#aggregation--statistics)
  - [Basic Aggregation](#basic-aggregation)
  - [Window Computation](#window-computation)
- [Data Visualization](#data-visualization)
- [Advanced Operations](#advanced-operations)
  - [Transactions](#transactions)
  - [Deduplication](#deduplication)
  - [Binning](#binning)
  - [Array Operations](#array-operations)
  - [Geolocation](#geolocation)
- [Data Persistence](#data-persistence)
- [Query Library](#query-library)
- [Best Practices](#best-practices)
- [Common Use Cases](#common-use-cases)

## Introduction

XQL (XSIAM Query Language) is a powerful query language designed for security analytics in the Cortex XSIAM platform. It allows security analysts to query, filter, transform, and analyze security data across multiple datasets. This guide provides a structured reference to help you master XQL syntax and the Cortex Data Model.

## Basic Concepts

### Dataset Selection

The first step in any XQL query is selecting the dataset to query against.

#### Basic Dataset Selection

```xql
dataset = xdr_data
```

#### Multiple Dataset Selection

```xql
dataset in (xdr_data, onelookup)
```

#### Cortex Data Model (XDM) Queries

```xql
datamodel dataset = xdr_data
datamodel dataset in (xdr_data, panw_ngfw_traffic_raw)
```

> **Note**: If you do not specify a dataset in your query, Cortex XDR runs the query against the default datasets configured. The default is typically `xdr_data`, which contains all of the endpoint and network data that Cortex XDR collects.

### Basic Search

Use the `search` command to perform free text search across your datasets.

```xql
search "127.0.0.1" dataset = xdr_data
```

Multiple search terms:

```xql
search "value1", "value2" dataset in (xdr_data, someLookup)
```

> **Important limitations**:
> - Should be the first stage in the query (only the config stage can precede search)
> - Queries containing search do not support the bin, comp, top, or dedup stages
> - Searches are limited to the last 90 days of data

### Filtering Data

The `filter` command allows you to specify conditions for which records should be returned.

#### Simple Filters

```xql
| filter actor_process_image_name in ("powershell.exe", "wscript.exe")
| filter action_upload < 10
```

#### Combining Conditions

```xql
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START and actor_process_image_name = "psexec.exe"
```

#### XDM Filters

```xql
| filter xdm.source.user.username = "newman"
```

#### Using XDM Constants (Enums)

```xql
| filter xdm.network.ip_protocol = XDM_CONST.IP_PROTOCOL_TCP
```

#### Using XDM Aliases

```xql
datamodel dataset = panw_ngfw_traffic_raw
| filter XDM_ALIAS.ipv4 = "10.10.10.10"
```

## Field Operations

### Fields Selection

Use the `fields` command to specify which fields should be returned in the results.

#### Basic Field Selection

```xql
| fields actor_process_image_path, action_network_http, event_id
```

#### Field Renaming

```xql
| fields actor_process_image_path as Process_Path, action_network_http, event_id
```

#### Excluding Fields

```xql
| fields -actor_process_image_path
```

#### XDM Field Selection

```xql
| fields fieldset.xdm_network, fieldset.xdm_endpoint, xdm.alert.name
```

### Field Transformation

Use the `alter` command to transform field values or create new fields.

#### Creating New Fields

```xql
| alter username = concat(user_first_name, user_last_name)
```

#### Using Existing Fields

```xql
| alter ip_address = coalesce(src_ip, dst_ip)
```

#### Extracting Data with Regex

```xql
| alter Service_Name = regextract(action_evtlog_message, "Service Name.*?(\\w+)"),0)
```

## Data Joining & Combining

### Joins

Use the `join` command to combine results from two queries.

```xql
join type=inner (dataset = mylookup | filter agent_os = macos) as myapple myapple.agent_os = agent_os_type
```

Join types:
- `inner` (default): Returns records that have matching values in both queries
- `left`: Returns all records from the left query and matching records from the right query
- `right`: Returns all records from the right query and matching records from the left query

Conflict strategies:
- `right` (default): Uses field values from the right query
- `left`: Uses field values from the left query
- `both`: Keeps both field values

### Unions

Use the `union` command to combine results from multiple queries or datasets.

#### Dataset Union

```xql
| union {datasetname}
```

#### Query Union

```xql
| union ({inner xql query})
```

## Aggregation & Statistics

### Basic Aggregation

Use the `comp` command for statistical computations across rows.

#### Counting Distinct Values

```xql
| comp count_distinct(dns_query_name) as Unique_Domain_Count by source_ip
```

#### Summing Values

```xql
| comp sum(Download) as total by Process_Path, Process_CMD addrawdata = true as raw_data
```

### Window Computation

Use the `windowcomp` command to calculate statistics over groups of rows.

```xql
dataset = xdr_data
| limit 100
| windowcomp count(dns_query_name) by agent_ip_addresses as count_dns_query_name
```

## Data Visualization

Use the `view` command to control how results are displayed.

#### Text Highlighting

```xql
| view highlight fields = host_name, dpt_name, values = "new-york"
```

#### Chart Creation

```xql
| view graph type = line
| view graph type = column
```

#### Column Ordering

```xql
| view column order = populated
```

## Advanced Operations

### Transactions

Use the `transaction` command to find sequences of related events.

#### Time-based Transactions

```xql
| transaction user, agent_id span = 1h timeshift = 1615353499
```

#### Start/End Condition Transactions

```xql
| transaction f1, f2 startswith="str_1" endswith="str2" maxevents=99
```

### Deduplication

Use the `dedup` command to remove duplicate records.

```xql
| dedup field1, field2 by asc field3
```

### Binning

Use the `bin` command to group data by quantity or time intervals.

#### Quantity Binning

```xql
| bin action_total_upload bins = 50
```

#### Time Binning

```xql
| bin _time span = 1h timeshift = 1615353499 timezone = "+08:00"
| bin _time span = 1h timeshift = 1615353499 timezone = "America/Los_Angeles"
```

### Array Operations

Use the `arrayexpand` command to expand multi-value arrays into separate events.

```xql
| arrayexpand array_values limit 3
```

### Geolocation

Use the `iploc` command to associate IP addresses with geolocation information.

```xql
| iploc action_remote_ip loc_city as city, loc_latlon
| iploc action_remote_ip suffix=_remote_id
```

## Data Persistence

Use the `target` command to save query results for future use.

#### Saving to a Dataset

```xql
| target type = dataset my_new_dataset
```

#### Saving to a Lookup

```xql
| target type = lookup lookup.csv
```

#### Appending vs. Overwriting

```xql
| target type=dataset append=false agents_per_country
```

## Query Library

Use the `call` command to reference saved queries.

#### Basic Call

```xql
call "CreateRole operation parsed to fields"
```

#### Call with Parameters

```xql
call "CreateRole operation parsed to fields" key_id = "1234"
```

## Best Practices

1. **Start Simple**: Begin with dataset selection and basic filtering before adding complex operations
2. **Limit Your Results**: Use `limit` to prevent performance issues with large result sets
3. **Use Appropriate Time Ranges**: Narrow down time ranges to improve query performance
4. **Consider Query Order**: The order of XQL stages matters - think of them as a pipeline
5. **Use Aliases**: Rename fields to improve readability
6. **Leverage XDM_ALIAS**: Use predefined field sets to simplify common queries
7. **Replace Null Values**: Use `replacenull` to handle missing data gracefully

## Common Use Cases

### Process Execution Monitoring

```xql
dataset = xdr_data
| filter event_type = ENUM.PROCESS and event_sub_type = ENUM.PROCESS_START
| filter actor_process_image_name in ("powershell.exe", "cmd.exe", "wscript.exe", "cscript.exe")
| fields timestamp_desc, agent_hostname, actor_process_image_path, actor_process_command_line
| sort desc timestamp_desc
| limit 100
```

### Network Connection Analysis

```xql
datamodel dataset = xdr_data
| filter XDM_ALIAS.network_connection
| fields xdm.source.process.file.name, xdm.source.process.pid, xdm.source.ipv4, xdm.target.ipv4, xdm.target.port
| limit 100
```

### Authentication Failures

```xql
preset = authentication_story
| filter action_result = "FAILURE"
| comp count() as failure_count by actor_effective_username, agent_hostname
| sort desc failure_count
| limit 20
```

---

## License

This documentation is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Palo Alto Networks for creating the Cortex XSIAM platform and XQL
- The security community for continually pushing the boundaries of security analytics

---

*Last updated: March 2025*

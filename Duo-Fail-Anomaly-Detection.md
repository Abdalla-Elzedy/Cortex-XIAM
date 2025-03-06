# Duo Authentication Failure Anomaly Detection with XQL


## What This Query Does

This XQL query for Cortex XSIAM analyzes Duo authentication logs to find users who have an unusually high number of failed login attempts on a given day. It compares each user's daily failure count against their own historical average to identify potentially suspicious activity.

## How It Works

1. The query extracts relevant information from the Duo logs:
   - User information
   - Device and location details
   - Time information (day of week, hour, etc.)

2. It filters for authentication failures (failed, denied, or fraud results)

3. It counts failures by user and day

4. It calculates the average number of failures for each user over the past week

5. It sets a threshold to identify unusual activity:
   - If the user has history: 3 times their daily average
   - If the user is new: 5 failures

6. It identifies anomalies where the failure count exceeds the threshold

7. It shows the results sorted by severity (most unusual first)

## Query

```
dataset = duo_duo_raw
| alter 
    formatted_time = format_timestamp("%A, %B %d, %Y %I:%M:%S %p", _time, "America/New_York"),
    user_name = json_extract_scalar(to_json_string(USER), "$.name"),
    access_device_ip = json_extract_scalar(to_json_string(ACCESS_DEVICE), "$.ip"),
    access_device_city = json_extract_scalar(to_json_string(ACCESS_DEVICE), "$.location.city"),
    access_device_state = json_extract_scalar(to_json_string(ACCESS_DEVICE), "$.location.state"),
    access_device_country = json_extract_scalar(to_json_string(ACCESS_DEVICE), "$.location.country"),
    day_of_week = extract_time(_time, "DAYOFWEEK"),
    hour_of_day = extract_time(_time, "HOUR"),
    day_bin = date_floor(_time, "d")
| filter result = "FAILURE" OR result = "FRAUD" OR result = "denied"
| comp 
    count() as failure_count,
    values(reason) as failure_reasons
    by user_name, day_bin
| windowcomp avg(failure_count) by user_name sort asc day_bin between -7 and -1 as avg_failures_per_day
| alter 
    threshold = if(avg_failures_per_day > 0, multiply(avg_failures_per_day, 3), 5)
| alter     is_anomaly = if(failure_count > threshold AND failure_count > 3, true, false)
| alter    anomaly_score = divide(failure_count, if(threshold > 0, threshold, 1)),
    failure_reason_list = arraystring(failure_reasons, ", ")
| filter is_anomaly = true
| fields 
    day_bin,
    user_name,
    failure_count,
    avg_failures_per_day,
    threshold,
    anomaly_score,
    failure_reason_list
| sort desc anomaly_score
```

## Interpreting the Results

The query output includes:

- **day_bin**: The day when the failures occurred
- **user_name**: The user who experienced the failures
- **failure_count**: Total number of failures that day
- **avg_failures_per_day**: User's historical daily average
- **threshold**: The number of failures needed to trigger an alert
- **anomaly_score**: How far above the threshold (higher numbers are more unusual)
- **failure_reason_list**: Types of failures experienced

Higher anomaly scores represent more unusual activity that may require investigation.

## Usage

This XQL query for Cortex XSIAM is helpful for:
- Finding potential brute force attacks
- Identifying compromised accounts
- Detecting unusual user behavior

# Duo Authentication Security Analysis: Impossible Travel Detection

This query identifies potential security risks by detecting users who have authenticated from different geographical locations within a timeframe that makes physical travel between the locations impossible.

```
dataset = duo_duo_raw 
| alter formatted_time = format_timestamp("%A, %B %d, %Y %I:%M:%S %p", _time, "America/New_York")
| alter 
    user_name = json_extract_scalar(to_json_string(USER), "$.name"),
    access_device_ip = json_extract_scalar(to_json_string(ACCESS_DEVICE), "$.ip"),
    access_device_city = json_extract_scalar(to_json_string(ACCESS_DEVICE), "$.location.city"),
    access_device_state = json_extract_scalar(to_json_string(ACCESS_DEVICE), "$.location.state"),
    access_device_country = json_extract_scalar(to_json_string(ACCESS_DEVICE), "$.location.country")
| filter access_device_city != null
| windowcomp lag(_time) by user_name sort asc _time as previous_time
| windowcomp lag(access_device_ip) by user_name sort asc _time as previous_ip
| windowcomp lag(access_device_city) by user_name sort asc _time as previous_city
| windowcomp lag(access_device_state) by user_name sort asc _time as previous_state
| windowcomp lag(access_device_country) by user_name sort asc _time as previous_country
| alter 
    hours_between = divide(timestamp_diff(_time, previous_time, "MINUTE"), 60),
    current_location = concat(access_device_city, ", ", access_device_state, ", ", access_device_country),
    previous_location = concat(previous_city, ", ", previous_state, ", ", previous_country)
| filter hours_between > 0 and hours_between < 6
| filter previous_city != null and previous_city != access_device_city
| filter current_location != null and current_location != ", ,"
| fields 
    formatted_time,
    user_name, 
    previous_time, 
    hours_between,
    access_device_ip,
    previous_ip,
    previous_location, 
    current_location
| sort desc formatted_time
```


# Duo Authentication: Impossible Travel Detection

This query identifies potential security risks by detecting users who have authenticated from different geographical locations within a timeframe that makes physical travel between the locations impossible.

```
dataset = duo_duo_raw 
| alter formatted_time = format_timestamp("%A, %B %d, %Y %I:%M:%S %p", _time, "America/New_York")
| filter reason != "bypass_user"
| alter 
    user_name = json_extract_scalar(to_json_string(USER), "$.name"),
    user_groups = json_extract_array(to_json_string(USER), "$.groups"),
    user_first_group = arrayindex(json_extract_array(to_json_string(USER), "$.groups"), 0),
    access_device_ip = json_extract_scalar(to_json_string(ACCESS_DEVICE), "$.ip"),
    access_device_name = json_extract_scalar(to_json_string(ACCESS_DEVICE), "$.name"),
    access_device_city = json_extract_scalar(to_json_string(ACCESS_DEVICE), "$.location.city"),
    access_device_state = json_extract_scalar(to_json_string(ACCESS_DEVICE), "$.location.state"),
    access_device_country = json_extract_scalar(to_json_string(ACCESS_DEVICE), "$.location.country"),
    app_name = json_extract_scalar(to_json_string(APPLICATION), "$.name")
| filter access_device_city != null
| windowcomp lag(_time) by user_name sort asc _time as previous_time
| windowcomp lag(access_device_ip) by user_name sort asc _time as previous_ip
| windowcomp lag(access_device_city) by user_name sort asc _time as previous_city
| windowcomp lag(access_device_state) by user_name sort asc _time as previous_state
| windowcomp lag(access_device_country) by user_name sort asc _time as previous_country
| windowcomp lag(access_device_name) by user_name sort asc _time as previous_device_name
| windowcomp lag(result) by user_name sort asc _time as previous_result
| windowcomp lag(reason) by user_name sort asc _time as previous_reason
| windowcomp lag(factor) by user_name sort asc _time as previous_factor
| windowcomp lag(app_name) by user_name sort asc _time as previous_app_name
| alter 
    hours_between_raw = divide(timestamp_diff(_time, previous_time, "MINUTE"), 60),
    minutes_between = timestamp_diff(_time, previous_time, "MINUTE") 
| alter     travel_time = if(minutes_between >= 60, 
                    format_string("%.1f hours", divide(minutes_between, 60)), 
                    format_string("%d minutes", minutes_between)),
    current_location = concat(access_device_city, ", ", access_device_state, ", ", access_device_country),
    previous_location = concat(previous_city, ", ", previous_state, ", ", previous_country),
    country_changed = if(previous_country != access_device_country, true, false),
    device_changed = if(access_device_name != previous_device_name, true, false) 
 | alter   risk_level = if(country_changed = true, 
                     if(hours_between_raw < 2, "CRITICAL", "HIGH"), 
                     if(hours_between_raw < 2, "HIGH", "MEDIUM")),
    factor_part = if(factor != null and factor != "", concat("", factor), ""),
    reason_part = if(reason != null and reason != "", concat("", reason), ""),
    result_part = if(result != null and result != "", concat("", result), ""),
    app_part = if(app_name != null and app_name != "", concat("App: ", app_name), ""),
    prev_factor_part = if(previous_factor != null and previous_factor != "", concat("", previous_factor), ""),
    prev_reason_part = if(previous_reason != null and previous_reason != "", concat("", previous_reason), ""),
    prev_result_part = if(previous_result != null and previous_result != "", concat("", previous_result), ""),
    prev_app_part = if(previous_app_name != null and previous_app_name != "", concat("App: ", previous_app_name), "")
| alter
    auth_parts = arrayfilter(arraycreate(app_part, factor_part, reason_part, result_part), "@element" != ""),
    prev_auth_parts = arrayfilter(arraycreate(prev_app_part, prev_factor_part, prev_reason_part, prev_result_part), "@element" != "")
| alter   
    auth_details = arraystring(auth_parts, " | "),
    prev_auth_details = arraystring(prev_auth_parts, " | ")
| filter hours_between_raw > 0 and hours_between_raw < 6
| filter previous_city != null and previous_city != access_device_city
| filter current_location != null and current_location != ", ,"
| fields 
    formatted_time,
    previous_time, 
    country_changed,
    device_changed,
    risk_level,
    user_name,
    previous_ip,
    prev_auth_details,
    previous_location,
    travel_time,
    current_location,
    auth_details,
    access_device_ip
| sort desc country_changed, asc risk_level, desc formatted_time
```


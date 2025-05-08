#!/bin/bash

LOG_FILE="access.log"  # Update this path if needed
REPORT_FILE="log_report.txt"

# Check if log file exists
if [ ! -f "$LOG_FILE" ]; then
    echo "Error: Log file $LOG_FILE not found!"
    exit 1
fi

# Initialize output
> "$REPORT_FILE"

echo "---- Log File Analysis Report ----" >> "$REPORT_FILE"
echo "Date: $(date)" >> "$REPORT_FILE"
echo "Analyzing file: $LOG_FILE" >> "$REPORT_FILE"
echo "=================================" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# 1. Request Counts
total_requests=$(wc -l < "$LOG_FILE")
get_requests=$(grep -c '"GET ' "$LOG_FILE")
post_requests=$(grep -c '"POST ' "$LOG_FILE")
other_requests=$((total_requests - get_requests - post_requests))

echo "==== REQUEST COUNTS ====" >> "$REPORT_FILE"
echo "Total requests: $total_requests" >> "$REPORT_FILE"
echo "GET requests: $get_requests ($(awk -v get="$get_requests" -v total="$total_requests" 'BEGIN {printf("%.2f%%", (get/total)*100)}'))" >> "$REPORT_FILE"
echo "POST requests: $post_requests ($(awk -v post="$post_requests" -v total="$total_requests" 'BEGIN {printf("%.2f%%", (post/total)*100)}'))" >> "$REPORT_FILE"
echo "Other requests: $other_requests ($(awk -v other="$other_requests" -v total="$total_requests" 'BEGIN {printf("%.2f%%", (other/total)*100)}'))" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# 2. Unique IPs and per-IP GET/POST count
unique_ips=$(awk '{print $1}' "$LOG_FILE" | sort -u | wc -l)

echo "==== IP ADDRESS ANALYSIS ====" >> "$REPORT_FILE"
echo "Unique IP addresses: $unique_ips" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"
echo "Top 10 most active IPs:" >> "$REPORT_FILE"
awk '{print $1}' "$LOG_FILE" | sort | uniq -c | sort -nr | head -10 | awk '{printf "%-15s %s requests\n", $2, $1}' >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

echo "Request methods by IP (top 10 IPs):" >> "$REPORT_FILE"
awk '{
    ip = $1;
    # Find the quoted request part
    for(i=1; i<=NF; i++) {
        if($i ~ /^"(GET|POST|PUT|DELETE)/) {
            # Extract just the method
            method = gensub(/^"([^[:space:]]+).*/, "\\1", "g", $i);
            break;
        }
    }
    # Count by IP and method
    count[ip][method]++;
}
END {
    # Calculate totals
    for(ip in count) {
        total = 0;
        for(method in count[ip]) {
            total += count[ip][method];
        }
        totals[ip] = total;
    }
    
    # Get top 10 IPs by request count
    for(ip in totals) {
        all_ips[i++] = ip;
    }
    # Simple sort for top 10
    for(i=0; i<length(all_ips)-1; i++) {
        for(j=i+1; j<length(all_ips); j++) {
            if(totals[all_ips[i]] < totals[all_ips[j]]) {
                temp = all_ips[i];
                all_ips[i] = all_ips[j];
                all_ips[j] = temp;
            }
        }
    }
    
    # Print top 10
    for(i=0; i<10 && i<length(all_ips); i++) {
        ip = all_ips[i];
        get_count = count[ip]["GET"] ? count[ip]["GET"] : 0;
        post_count = count[ip]["POST"] ? count[ip]["POST"] : 0;
        other_count = totals[ip] - get_count - post_count;
        printf "%-15s GET: %-5d POST: %-5d Other: %-5d\n", 
            ip, get_count, post_count, other_count;
    }
}' "$LOG_FILE" >> "$REPORT_FILE"

# 3. Failed Requests
failed_requests=$(awk '$9 ~ /^[45]/ {count++} END {print count+0}' "$LOG_FILE")
fail_percent=$(awk -v fail="$failed_requests" -v total="$total_requests" 'BEGIN { printf("%.2f", (fail / total) * 100) }')
server_errors=$(awk '$9 ~ /^5/ {count++} END {print count+0}' "$LOG_FILE")
client_errors=$(awk '$9 ~ /^4/ {count++} END {print count+0}' "$LOG_FILE")

echo "==== ERROR ANALYSIS ====" >> "$REPORT_FILE"
echo "Failed requests: $failed_requests ($fail_percent%)" >> "$REPORT_FILE"
echo "Client errors (4xx): $client_errors ($(awk -v err="$client_errors" -v total="$total_requests" 'BEGIN { printf("%.2f%%", (err / total) * 100) }'))" >> "$REPORT_FILE"
echo "Server errors (5xx): $server_errors ($(awk -v err="$server_errors" -v total="$total_requests" 'BEGIN { printf("%.2f%%", (err / total) * 100) }'))" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Most common error status codes
echo "Top 5 error status codes:" >> "$REPORT_FILE"
awk '$9 ~ /^[45]/ {codes[$9]++} END {for (c in codes) print c, codes[c]}' "$LOG_FILE" | sort -k2nr | head -5 >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# 4. Top User (Most Active IP)
top_ip=$(awk '{ips[$1]++} END {for (ip in ips) print ips[ip], ip}' "$LOG_FILE" | sort -nr | head -1)
top_ip_count=$(echo "$top_ip" | awk '{print $1}')
top_ip_address=$(echo "$top_ip" | awk '{print $2}')
top_ip_percent=$(awk -v count="$top_ip_count" -v total="$total_requests" 'BEGIN { printf("%.2f", (count / total) * 100) }')

echo "==== USER BEHAVIOR ====" >> "$REPORT_FILE"
echo "Most active IP: $top_ip_address with $top_ip_count requests ($top_ip_percent% of all traffic)" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# 5. Enhanced Daily Request Averages with full date parsing
echo "==== TEMPORAL ANALYSIS ====" >> "$REPORT_FILE"
echo "Daily request statistics:" >> "$REPORT_FILE"
awk '{
    split($4, a, "["); 
    split(a[2], b, "/");
    day=b[1];
    month=b[2];
    year=b[3];
    date=sprintf("%02d/%02d/%04d", day, month, year);
    requests[date]++;
    total++;
} 
END {
    PROCINFO["sorted_in"] = "@ind_str_asc";
    min_date=""; max_date=""; sum=0; count=0;
    for (d in requests) {
        if (min_date == "" || d < min_date) min_date = d;
        if (max_date == "" || d > max_date) max_date = d;
        printf "%s: %d requests\n", d, requests[d];
        sum += requests[d];
        count++;
    }
    if (count > 0) {
        printf "\nDate range: %s to %s\n", min_date, max_date;
        printf "Average daily requests: %.2f\n", sum/count;
        
        # Calculate actual days in range for more accurate average
        split(min_date, d1, "/");
        split(max_date, d2, "/");
        epoch1 = mktime(d1[3]" "d1[2]" "d1[1]" 00 00 00");
        epoch2 = mktime(d2[3]" "d2[2]" "d2[1]" 00 00 00");
        days = (epoch2 - epoch1) / 86400 + 1;
        printf "Average including days with no requests: %.2f\n", total/days;
    }
}' "$LOG_FILE" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# 6. Enhanced Failure by Day with failure rates
echo "Failure requests by day (with failure rates):" >> "$REPORT_FILE"
awk '{
    split($4, a, "["); 
    split(a[2], b, "/");
    date=sprintf("%02d/%02d/%04d", b[1], b[2], b[3]);
    total_reqs[date]++;
    if ($9 ~ /^[45]/) {
        fails[date]++;
    }
} 
END {
    PROCINFO["sorted_in"] = "@ind_str_asc";
    for (d in total_reqs) {
        fail_count = fails[d] ? fails[d] : 0;
        rate = total_reqs[d] > 0 ? (fail_count/total_reqs[d])*100 : 0;
        printf "%s: %d failures (%.2f%% failure rate)\n", d, fail_count, rate;
    }
}' "$LOG_FILE" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Requests by Hour with enhanced formatting
echo "Hourly request distribution:" >> "$REPORT_FILE"
awk '{
    split($4, a, "["); 
    split(a[2], b, ":"); 
    hour=b[2];
    hours[hour]++;
    total++;
} 
END {
    printf "%-15s %-10s %s\n", "Time", "Requests", "Percentage";
    printf "%-15s %-10s %s\n", "----", "--------", "----------";
    for (h=0; h<24; h++) {
        hour = sprintf("%02d", h);
        count = hours[hour] ? hours[hour] : 0;
        percent = (count/total)*100;
        printf "%s:00-%-7s %-10d %.2f%%\n", hour, hour":59", count, percent;
    }
}' "$LOG_FILE" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Request trends (simplified)
echo "Request trend by hour:" >> "$REPORT_FILE"
awk '{
    split($4, a, "["); 
    split(a[2], b, ":"); 
    hours[b[2]]++
} 
END {
    prev = 0;
    for (h=0; h<24; h++) {
        hour = sprintf("%02d", h);
        current = hours[hour] ? hours[hour] : 0;
        if (prev > 0) {
            change = current - prev;
            percent = prev > 0 ? (change/prev)*100 : 0;
            trend = change > 0 ? "↑" : (change < 0 ? "↓" : "→");
            printf "%s:00: %d requests %s %.1f%% from previous hour\n", 
                  hour, current, trend, (percent >= 0 ? percent : -percent);
        } else {
            printf "%s:00: %d requests\n", hour, current;
        }
        prev = current;
    }
}' "$LOG_FILE" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Status code breakdown with better formatting
echo "==== STATUS CODE ANALYSIS ====" >> "$REPORT_FILE"
echo "Status code distribution:" >> "$REPORT_FILE"
awk '{
    codes[$9]++;
    total++;
} 
END {
    printf "%-6s %-10s %s\n", "Code", "Count", "Percentage";
    printf "%-6s %-10s %s\n", "----", "-----", "----------";
    for (c in codes) {
        if (c == "") c = "N/A";
        percent = (codes[c]/total)*100;
        printf "%-6s %-10d %.2f%%\n", c, codes[c], percent;
    }
}' "$LOG_FILE" | sort >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Most Active User by Method
echo "==== METHOD USAGE BY USERS ====" >> "$REPORT_FILE"
echo "Most GET-heavy IP:" >> "$REPORT_FILE"
grep '"GET ' "$LOG_FILE" | awk '{print $1}' | sort | uniq -c | sort -nr | head -1 | 
    awk '{printf "%-15s %d GET requests (%.2f%% of all GET requests)\n", $2, $1, ($1/'"$get_requests"')*100}' >> "$REPORT_FILE"

echo "Most POST-heavy IP:" >> "$REPORT_FILE"
grep '"POST ' "$LOG_FILE" | awk '{print $1}' | sort | uniq -c | sort -nr | head -1 | 
    awk '{printf "%-15s %d POST requests (%.2f%% of all POST requests)\n", $2, $1, ($1/'"$post_requests"')*100}' >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Enhanced Failure Patterns with rates
echo "==== ERROR PATTERNS ====" >> "$REPORT_FILE"
echo "Failure distribution by hour (with failure rates):" >> "$REPORT_FILE"
awk '{
    split($4, a, ":"); 
    hour=a[2];
    total_reqs[hour]++;
    if ($9 ~ /^[45]/) {
        fails[hour]++;
    }
} 
END {
    printf "%-15s %-10s %s\n", "Hour", "Failures", "Failure Rate";
    printf "%-15s %-10s %s\n", "----", "--------", "------------";
    for (h=0; h<24; h++) {
        hour = sprintf("%02d", h);
        fail_count = fails[hour] ? fails[hour] : 0;
        total = total_reqs[hour] ? total_reqs[hour] : 0;
        rate = total > 0 ? (fail_count/total)*100 : 0;
        printf "%s:00-%-7s %-10d %.2f%%\n", hour, hour":59", fail_count, rate;
    }
}' "$LOG_FILE" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Pattern: Failing URLs with enhanced analysis
echo "Top 5 URLs with most errors (with error rates):" >> "$REPORT_FILE"
awk '{
    url=$7;
    total_urls[url]++;
    if ($9 ~ /^[45]/) {
        fail_urls[url]++;
    }
} 
END {
    for (url in fail_urls) {
        rate = (fail_urls[url]/total_urls[url])*100;
        printf "%d %s %.2f%%\n", fail_urls[url], url, rate;
    }
}' "$LOG_FILE" | sort -nr | head -5 | 
awk '{
    printf "%-40s %d errors (%.2f%% error rate)\n", $2, $1, $3;
}' >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Enhanced Security analysis
echo "==== SECURITY ANALYSIS ====" >> "$REPORT_FILE"

# Check for rapid requests from single IPs with thresholds
echo "IPs with rapid succession requests (potential DoS):" >> "$REPORT_FILE"
awk '{
    ip=$1; 
    split($4, datetime, ":");
    timestamp = datetime[1]":"datetime[2]":"datetime[3];
    if (ip == last_ip && timestamp == last_timestamp) {
        count[ip]++;
    }
    last_ip = ip;
    last_timestamp = timestamp;
} 
END {
    threshold = 30;  # Requests per second threshold
    for (ip in count) {
        if (count[ip] > threshold) {
            printf "%-15s %d rapid requests (%.2f req/sec)\n", ip, count[ip], count[ip]/1;
        }
    }
}' "$LOG_FILE" | sort -k2nr >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Enhanced suspicious activity detection
echo "IPs with high rate of authentication failures or suspicious URL patterns:" >> "$REPORT_FILE"
awk 'tolower($7) ~ /login|admin|wp-login|password|auth|config|\.env|\.git/ && $9 ~ /4[0-9][0-9]/ {
    ip_count[$1]++;
    suspicious[$1][$7]++;
} 
END {
    threshold = 5;  # Minimum suspicious requests to report
    for (ip in ip_count) {
        if (ip_count[ip] > threshold) {
            printf "%-15s %d suspicious requests\n", ip, ip_count[ip];
            # Uncomment to show specific suspicious URLs:
            # for (url in suspicious[ip]) {
            #     printf "    %s\n", url;
            # }
        }
    }
}' "$LOG_FILE" | sort -k2nr >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Generate insights and recommendations with more context
echo "==== INSIGHTS AND RECOMMENDATIONS ====" >> "$REPORT_FILE"
echo "Based on the analysis of the log file, here are some key insights and recommendations:" >> "$REPORT_FILE"
echo >> "$REPORT_FILE"

# Check for high error rate
if (( $(echo "$fail_percent > 5" | bc -l) )); then
    echo "1. HIGH ERROR RATE ALERT: $fail_percent% of requests resulted in errors." >> "$REPORT_FILE"
    
    # Get top error codes
    top_error_code=$(awk '$9 ~ /^[45]/ {codes[$9]++} END {for (c in codes) print codes[c], c}' "$LOG_FILE" | sort -nr | head -1 | awk '{print $2}')
    top_error_count=$(awk '$9 ~ /^[45]/ {codes[$9]++} END {for (c in codes) print codes[c], c}' "$LOG_FILE" | sort -nr | head -1 | awk '{print $1}')
    top_error_percent=$(awk -v count="$top_error_count" -v total="$total_requests" 'BEGIN { printf("%.2f", (count / total) * 100) }')
    
    echo "   - Most common error: $top_error_code ($top_error_count occurrences, $top_error_percent% of all requests)" >> "$REPORT_FILE"
    
    # Check specific error types
    if (( server_errors > 0 )); then
        echo "   - Server errors (5xx) indicate infrastructure or application issues. Review application logs and server status." >> "$REPORT_FILE"
    fi
    
    if (( client_errors > 0 )); then
        echo "   - High rate of client errors (4xx) may indicate:" >> "$REPORT_FILE"
        echo "     * Broken links or outdated bookmarks" >> "$REPORT_FILE"
        echo "     * Scanning attempts or exploitation attempts" >> "$REPORT_FILE"
        echo "     * Misconfigured clients or applications" >> "$REPORT_FILE"
    fi
    
    # Look at top error URLs
    echo "   - Focus debugging efforts on the most problematic URLs:" >> "$REPORT_FILE"
    awk '$9 ~ /^[45]/ {print $7}' "$LOG_FILE" | sort | uniq -c | sort -nr | head -3 | 
        awk '{printf "     * %-40s (%d errors)\n", $2, $1}' >> "$REPORT_FILE"
fi

# Enhanced Traffic pattern analysis
high_traffic_hour=$(awk '{split($4, a, ":"); hours[a[2]]++} END {
    max=0; max_hour=0;
    for (h=0; h<24; h++) {
        hour = sprintf("%02d", h);
        if (hours[hour] > max) {
            max = hours[hour];
            max_hour = hour;
        }
    }
    print max_hour;
}' "$LOG_FILE")

high_traffic_count=$(awk -v hour="$high_traffic_hour" '{split($4, a, ":"); if (a[2] == hour) count++} END {print count}' "$LOG_FILE")
high_traffic_percent=$(awk -v count="$high_traffic_count" -v total="$total_requests" 'BEGIN { printf("%.2f", (count / total) * 100) }')

low_traffic_hour=$(awk '{split($4, a, ":"); hours[a[2]]++} END {
    min=999999; min_hour=0;
    for (h=0; h<24; h++) {
        hour = sprintf("%02d", h);
        if ((hour in hours) && (hours[hour] < min || min == 999999)) {
            min = hours[hour];
            min_hour = hour;
        }
    }
    print min_hour;
}' "$LOG_FILE")

low_traffic_count=$(awk -v hour="$low_traffic_hour" '{split($4, a, ":"); if (a[2] == hour) count++} END {print count+0}' "$LOG_FILE")
low_traffic_percent=$(awk -v count="$low_traffic_count" -v total="$total_requests" 'BEGIN { printf("%.2f", (count / total) * 100) }')

echo "2. TRAFFIC PATTERNS:" >> "$REPORT_FILE"
echo "   - Peak traffic occurs around $high_traffic_hour:00 with $high_traffic_count requests ($high_traffic_percent% of daily traffic)." >> "$REPORT_FILE"
echo "     Ensure system resources are optimized for this time." >> "$REPORT_FILE"
echo "   - Traffic is lowest around $low_traffic_hour:00 with $low_traffic_count requests ($low_traffic_percent% of daily traffic)." >> "$REPORT_FILE"
echo "     Consider scheduling maintenance during this period." >> "$REPORT_FILE"

# Enhanced IP concentration analysis
top_ip_threshold=30
if (( $(echo "$top_ip_percent > $top_ip_threshold" | bc -l) )); then
    echo "3. TRAFFIC CONCENTRATION ALERT:" >> "$REPORT_FILE"
    echo "   - $top_ip_address accounts for $top_ip_percent% of all traffic, which is unusually high." >> "$REPORT_FILE"
    echo "   - Investigate if this is legitimate traffic or potential abuse:" >> "$REPORT_FILE"
    echo "     * Check the user agent and request patterns for this IP" >> "$REPORT_FILE"
    echo "     * Verify if this is a known client or service" >> "$REPORT_FILE"
    echo "     * Consider implementing rate limiting if suspicious" >> "$REPORT_FILE"
else
    echo "3. TRAFFIC DISTRIBUTION:" >> "$REPORT_FILE"
    echo "   - Traffic is distributed across $unique_ips unique IP addresses." >> "$REPORT_FILE"
    echo "   - The most active IP ($top_ip_address) accounts for $top_ip_percent% of all traffic." >> "$REPORT_FILE"
fi

# Method usage analysis with more context
if (( post_requests > get_requests )); then
    echo "4. UNUSUAL METHOD DISTRIBUTION:" >> "$REPORT_FILE"
    echo "   - POST requests ($post_requests) exceed GET requests ($get_requests), which is uncommon for typical web traffic." >> "$REPORT_FILE"
    echo "   - Possible explanations:" >> "$REPORT_FILE"
    echo "     * API-heavy application" >> "$REPORT_FILE"
    echo "     * Form submission service" >> "$REPORT_FILE"
    echo "     * Potential form/API abuse" >> "$REPORT_FILE"
    echo "   - Investigate POST request endpoints and payloads if unexpected." >> "$REPORT_FILE"
fi

# Enhanced Security recommendations
echo "5. SECURITY RECOMMENDATIONS:" >> "$REPORT_FILE"
echo "   - Implement rate limiting to prevent abuse from single IP addresses:" >> "$REPORT_FILE"
echo "     * Consider limits like 1000 requests/minute per IP" >> "$REPORT_FILE"
echo "     * Implement stricter limits for sensitive endpoints" >> "$REPORT_FILE"
echo "   - Consider using a Web Application Firewall to block suspicious traffic patterns." >> "$REPORT_FILE"
echo "   - Regularly review authentication endpoints for brute force attempts." >> "$REPORT_FILE"
echo "   - Monitor error rates and investigate anomalies promptly." >> "$REPORT_FILE"
echo "   - Review IPs flagged in the security analysis section." >> "$REPORT_FILE"

# Enhanced Performance recommendations
echo "6. PERFORMANCE RECOMMENDATIONS:" >> "$REPORT_FILE"
echo "   - Schedule resource-intensive tasks during low-traffic periods (around $low_traffic_hour:00)." >> "$REPORT_FILE"
echo "   - Ensure sufficient capacity during peak hours (around $high_traffic_hour:00)." >> "$REPORT_FILE"
if (( server_errors > 0 )); then
    echo "   - Address server errors to improve system reliability and user experience." >> "$REPORT_FILE"
fi
echo "   - Consider caching for endpoints with high traffic but low change frequency." >> "$REPORT_FILE"
echo "   - Optimize endpoints with high error rates (see error patterns section)." >> "$REPORT_FILE"

# Add summary of key findings
echo >> "$REPORT_FILE"
echo "==== KEY FINDINGS SUMMARY ====" >> "$REPORT_FILE"
echo "1. Total requests: $total_requests" >> "$REPORT_FILE"
echo "2. Error rate: $fail_percent%" >> "$REPORT_FILE"
echo "3. Unique IPs: $unique_ips" >> "$REPORT_FILE"
echo "4. Peak traffic hour: $high_traffic_hour:00 ($high_traffic_count requests)" >> "$REPORT_FILE"
echo "5. Most active IP: $top_ip_address ($top_ip_count requests)" >> "$REPORT_FILE"
echo "6. Most common error: $top_error_code ($top_error_count occurrences)" >> "$REPORT_FILE"

echo >> "$REPORT_FILE"
echo "==== END OF REPORT ====" >> "$REPORT_FILE"

echo "Analysis complete. Report saved to $REPORT_FILE"
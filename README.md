# Log File Analysis Tool

## Overview

This repository contains a Bash script for analyzing web server log files. The tool processes standard format access logs and generates comprehensive statistical reports, including request patterns, error analysis, and potential security insights.

## Task Requirements

The log analysis tool extracts the following information from server access logs:

1. **Request Counts**

   - Total number of requests
   - GET/POST request distribution
   - Other request methods

2. **IP Address Analysis**

   - Number of unique IP addresses
   - Most active IP addresses
   - Request method distribution by IP

3. **Error Analysis**

   - Failed request counts (4xx and 5xx status codes)
   - Error rate percentage
   - Most common error codes

4. **Temporal Analysis**

   - Daily request statistics
   - Request distribution by hour
   - Traffic trends and patterns

5. **Security Analysis**

   - Potential DoS attempts
   - Suspicious URL access patterns
   - Authentication failure detection

6. **Insights and Recommendations**
   - Data-driven suggestions for improvement
   - Potential security concerns
   - Performance optimization recommendations

## How It Works

The script uses common Unix/Linux text processing tools, including `awk`, `grep`, and `sort`, to extract and analyze data from the log file. It works with standard Apache/Nginx access log formats.

## Installation

No installation is required beyond having a standard Bash shell environment.

### Prerequisites

- Bash shell (version 4.0 or higher recommended)
- Common Unix utilities: `awk`, `grep`, `sort`, `uniq`, `wc`

## Usage

1. Place your access log file in the same directory as the script or update the `LOG_FILE` variable in the script.

2. Make the script executable:

   ```bash
   chmod +x analyzer.sh
   ```

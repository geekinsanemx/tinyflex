# HackRF HTTP/TCP Server - Usage Examples

This document provides comprehensive examples and use cases for the HackRF HTTP/TCP Server.

## Quick Start

### 1. Basic Setup
```bash
# Start server with default configuration
./hackrf_http_server

# Start with verbose logging to see detailed processing
./hackrf_http_server --verbose

# Start in debug mode (no transmission, creates IQ file)
./hackrf_http_server --debug --verbose
```

### 2. Send Your First Message
```bash
# HTTP API (modern, recommended)
curl -X POST http://localhost:16180/ \
  -u admin:passw0rd \
  -H "Content-Type: application/json" \
  -d '{"message": "Hello World"}'

# TCP Serial (legacy)
echo '37137|Hello World|931937500' | nc localhost 16175
```

## HTTP JSON API Examples

### Basic Messages
```bash
# Minimal message (uses default capcode 37137 and default frequency)
curl -X POST http://localhost:16180/ \
  -u admin:passw0rd \
  -H "Content-Type: application/json" \
  -d '{"message": "Test message"}'

# Message with custom capcode
curl -X POST http://localhost:16180/ \
  -u admin:passw0rd \
  -H "Content-Type: application/json" \
  -d '{"capcode": 1122334, "message": "Custom capcode"}'

# Complete message with all parameters
curl -X POST http://localhost:16180/ \
  -u admin:passw0rd \
  -H "Content-Type: application/json" \
  -d '{
    "capcode": 1122334,
    "message": "Complete message with frequency",
    "frequency": 925516000
  }'
```

### Real-World Scenarios
```bash
# Emergency alert
curl -X POST http://localhost:16180/ \
  -u admin:passw0rd \
  -H "Content-Type: application/json" \
  -d '{
    "capcode": 911911,
    "message": "EMERGENCY: Fire alarm activated in Building A",
    "frequency": 931937500
  }'

# System notification
curl -X POST http://localhost:16180/ \
  -u admin:passw0rd \
  -H "Content-Type: application/json" \
  -d '{
    "capcode": 12345,
    "message": "Server maintenance scheduled for 2AM-4AM tonight"
  }'

# Status update
curl -X POST http://localhost:16180/ \
  -u admin:passw0rd \
  -H "Content-Type: application/json" \
  -d '{
    "message": "All systems operational - $(date)",
    "capcode": 99999
  }'
```

### Error Testing
```bash
# Test authentication failure (should return 401)
curl -v -X POST http://localhost:16180/ \
  -u admin:wrongpassword \
  -H "Content-Type: application/json" \
  -d '{"message": "This will fail"}'

# Test missing message field (should return 400)
curl -v -X POST http://localhost:16180/ \
  -u admin:passw0rd \
  -H "Content-Type: application/json" \
  -d '{"capcode": 12345}'

# Test invalid JSON (should return 400)
curl -v -X POST http://localhost:16180/ \
  -u admin:passw0rd \
  -H "Content-Type: application/json" \
  -d '{"message": "missing quote}'

# Test wrong method (should return 405)
curl -v -X GET http://localhost:16180/ \
  -u admin:passw0rd
```

## TCP Serial Protocol Examples

### Basic Usage
```bash
# Simple message
echo '12345|Hello from TCP|931937500' | nc localhost 16175

# Message with timeout to prevent hanging
echo '99999|Status update|925516000' | timeout 10 nc localhost 16175

# Multiple messages
{
  echo '11111|First message|931937500'
  echo '22222|Second message|931937500'
  echo '33333|Third message|931937500'
} | nc localhost 16175
```

### Scripted Usage
```bash
#!/bin/bash
# send_alert.sh - Send alert via TCP protocol

CAPCODE=${1:-37137}
MESSAGE=${2:-"Default alert message"}
FREQUENCY=${3:-931937500}

echo "${CAPCODE}|${MESSAGE}|${FREQUENCY}" | nc localhost 16175
if [ $? -eq 0 ]; then
    echo "Alert sent successfully"
else
    echo "Failed to send alert"
    exit 1
fi
```

## Authentication Management

### Setting Up Users
```bash
# Create new passwords file with first user
htpasswd -c passwords admin

# Add additional users with bcrypt (recommended)
htpasswd -B passwords operator
htpasswd -B passwords emergency
htpasswd -B passwords monitoring

# Add user with MD5 (more compatible)
htpasswd -m passwords legacy_system

# Verify passwords
htpasswd -v passwords admin
htpasswd -v passwords operator
```

### Password File Management
```bash
# View all users
cut -d: -f1 passwords

# Delete a user
htpasswd -D passwords old_user

# Update password
htpasswd -B passwords existing_user

# Secure the file
chmod 600 passwords
chown hackrf:hackrf passwords  # If running as hackrf user
```

## Advanced Configuration

### Custom Configuration Files
```bash
# Create production config
cat > production.config << EOF
BIND_ADDRESS=0.0.0.0
SERIAL_LISTEN_PORT=16175
HTTP_LISTEN_PORT=16180
SAMPLE_RATE=8000000
BITRATE=3200
AMPLITUDE=100
TX_GAIN=30
DEFAULT_FREQUENCY=931937500
EOF

# Use custom config (rename to config.ini)
mv production.config config.ini
./hackrf_http_server --verbose
```

### Environment Variable Override
```bash
# Override specific settings
export TX_GAIN=25
export AMPLITUDE=90
./hackrf_http_server --verbose

# Disable serial protocol
export SERIAL_LISTEN_PORT=0
./hackrf_http_server --verbose
```

## Monitoring and Logging

### Comprehensive Logging
```bash
# Full verbose logging to file
./hackrf_http_server --verbose 2>&1 | tee hackrf_server.log

# Monitor in real-time
tail -f hackrf_server.log

# Filter for specific events
grep "Message Processing" hackrf_server.log
grep "HTTP Response" hackrf_server.log
grep "ERROR" hackrf_server.log
```

### Statistics and Analysis
```bash
# Count successful transmissions
grep -c "Message Processing Completed" hackrf_server.log

# Show HTTP response codes
grep "HTTP Response sent" hackrf_server.log | grep -o "Status: [0-9]*" | sort | uniq -c

# Show client connections
grep "Client connected" hackrf_server.log

# Extract transmission times
grep "transmission time" hackrf_server.log | grep -o "[0-9]*\.[0-9]* ms"
```

## Debugging and Development

### Debug Mode Usage
```bash
# Generate IQ files without transmission
./hackrf_http_server --debug --verbose

# Send test message to generate IQ file
curl -X POST http://localhost:16180/ \
  -u admin:passw0rd \
  -H "Content-Type: application/json" \
  -d '{"message": "Debug test message"}'

# Analyze generated IQ file with GNU Radio or other tools
ls -la flexserver_output.iq
```

### Signal Analysis
```bash
# View IQ file properties
file flexserver_output.iq
ls -lh flexserver_output.iq

# Convert to different formats (if needed)
# Note: This requires additional tools like GNU Radio
```

### Testing Without HackRF
```bash
# Debug mode doesn't require HackRF device
./hackrf_http_server --debug --verbose
# Perfect for development and testing
```

## Integration Examples

### Shell Script Integration
```bash
#!/bin/bash
# monitoring_alert.sh - System monitoring alert script

ALERT_URL="http://localhost:16180/"
AUTH="admin:passw0rd"

send_alert() {
    local message="$1"
    local capcode="${2:-99999}"

    response=$(curl -s -w "%{http_code}" -X POST "$ALERT_URL" \
        -u "$AUTH" \
        -H "Content-Type: application/json" \
        -d "{\"capcode\": $capcode, \"message\": \"$message\"}")

    http_code="${response: -3}"

    if [ "$http_code" = "200" ]; then
        echo "Alert sent successfully"
        return 0
    else
        echo "Alert failed with HTTP code: $http_code"
        return 1
    fi
}

# Usage examples
send_alert "System startup completed" 11111
send_alert "High CPU usage detected" 22222
send_alert "Backup completed successfully" 33333
```

### Python Integration
```python
#!/usr/bin/env python3
# hackrf_client.py - Python client for HackRF server

import requests
import json
import sys
from requests.auth import HTTPBasicAuth

class HackRFClient:
    def __init__(self, base_url="http://localhost:16180", username="admin", password="passw0rd"):
        self.base_url = base_url
        self.auth = HTTPBasicAuth(username, password)
        self.headers = {"Content-Type": "application/json"}

    def send_message(self, message, capcode=None, frequency=None):
        """Send a message via HTTP API"""
        payload = {"message": message}

        if capcode:
            payload["capcode"] = capcode
        if frequency:
            payload["frequency"] = frequency

        try:
            response = requests.post(
                self.base_url,
                auth=self.auth,
                headers=self.headers,
                json=payload,
                timeout=30
            )

            return {
                "success": response.status_code == 200,
                "status_code": response.status_code,
                "response": response.json() if response.headers.get("content-type", "").startswith("application/json") else response.text
            }

        except requests.exceptions.RequestException as e:
            return {
                "success": False,
                "error": str(e)
            }

    def test_connection(self):
        """Test server connectivity"""
        try:
            response = requests.get(self.base_url, timeout=5)
            return response.status_code == 405  # Should return Method Not Allowed for GET
        except:
            return False

# Usage examples
if __name__ == "__main__":
    client = HackRFClient()

    # Test connection
    if not client.test_connection():
        print("ERROR: Cannot connect to HackRF server")
        sys.exit(1)

    # Send messages
    result = client.send_message("Python test message", capcode=12345)
    print(f"Result: {result}")

    result = client.send_message("Emergency alert", capcode=911911, frequency=931937500)
    print(f"Emergency alert result: {result}")
```

### Cron Integration
```bash
# Add to crontab for scheduled messages
# crontab -e

# Send hourly status message
0 * * * * echo '99999|Hourly status check - $(date)|931937500' | nc localhost 16175

# Send daily backup notification
0 2 * * * curl -s -X POST http://localhost:16180/ -u admin:passw0rd -H "Content-Type: application/json" -d '{"message": "Daily backup starting", "capcode": 88888}'

# Weekly system health check
0 9 * * 1 /usr/local/bin/system_health_check.sh | /usr/local/bin/send_to_hackrf.sh
```

## Performance and Production

### High-Volume Usage
```bash
# For high message volume, consider:
# 1. Increase sample rate for better quality
export SAMPLE_RATE=8000000

# 2. Use higher bitrate
export BITRATE=3200

# 3. Monitor system resources
./hackrf_http_server --verbose &
SERVER_PID=$!

# Monitor CPU and memory usage
while kill -0 $SERVER_PID 2>/dev/null; do
    ps -p $SERVER_PID -o %cpu,%mem,cmd
    sleep 60
done
```

### Load Testing
```bash
# Simple load test script
#!/bin/bash
for i in {1..100}; do
    curl -s -X POST http://localhost:16180/ \
        -u admin:passw0rd \
        -H "Content-Type: application/json" \
        -d "{\"message\": \"Load test message $i\"}" &

    if [ $((i % 10)) -eq 0 ]; then
        wait  # Wait for batch to complete
        echo "Completed batch: $i"
    fi
done
wait
echo "Load test completed"
```

## Troubleshooting Examples

### Network Issues
```bash
# Check if ports are in use
netstat -tlnp | grep :16180
netstat -tlnp | grep :16175

# Test port connectivity
nc -zv localhost 16180
nc -zv localhost 16175

# Check firewall (if applicable)
sudo ufw status
sudo iptables -L -n
```

### HackRF Issues
```bash
# Check HackRF device
hackrf_info

# Check USB connection
lsusb | grep -i hackrf

# Test HackRF transmission
hackrf_transfer -t /dev/zero -f 915000000 -s 2000000 -x 0

# Check permissions
ls -la /dev/bus/usb/*/*
groups $USER  # Should include 'plugdev'
```

### Authentication Issues
```bash
# Verify password file
ls -la passwords
file passwords

# Test password verification
htpasswd -v passwords admin

# Check file permissions
chmod 600 passwords

# Verify base64 encoding manually
echo -n "admin:passw0rd" | base64
# Should match the Authorization header (minus "Basic ")
```

This comprehensive examples guide should help users understand and utilize all the features of the enhanced HackRF HTTP/TCP Server.

# HackRF HTTP/TCP Server

A dual-protocol FLEX paging server for HackRF that supports both legacy TCP serial protocol and modern HTTP JSON API with authentication. Features comprehensive verbose logging and standard HTTP response codes for seamless integration with cloud services like AWS Lambda.

## Features

- **Dual Protocol Support**: Both TCP serial and HTTP JSON APIs
- **HTTP Basic Authentication**: Secure access with htpasswd-compatible password files
- **Emergency Message Resynchronization (EMR)**: Automatic sync for reliable transmission
- **Comprehensive Verbose Logging**: Detailed pipeline visibility for debugging and monitoring
- **Standard HTTP Response Codes**: AWS Lambda and cloud service compatible
- **Debug Mode**: Signal analysis with IQ file output without transmission
- **Flexible Configuration**: File-based or environment variable configuration
- **Port Control**: Independent enable/disable for each protocol

## Configuration

The server reads configuration from `config.ini` (preferred) or environment variables as fallback.

### config.ini
```ini
# Network Configuration
BIND_ADDRESS=127.0.0.1
SERIAL_LISTEN_PORT=16175    # TCP port for serial protocol (0 = disabled)
HTTP_LISTEN_PORT=16180      # HTTP port for JSON API (0 = disabled)

# HackRF Configuration  
SAMPLE_RATE=2000000
BITRATE=1600
AMPLITUDE=127
FREQ_DEV=2400
TX_GAIN=0

# Default frequency to use when not specified in HTTP requests
DEFAULT_FREQUENCY=931937500
```

### Configuration Parameters

- **BIND_ADDRESS**: IP address to bind servers to (default: 127.0.0.1)
- **SERIAL_LISTEN_PORT**: TCP port for legacy serial protocol (default: 16175, set to 0 to disable)
- **HTTP_LISTEN_PORT**: HTTP port for JSON API (default: 16180, set to 0 to disable)
- **SAMPLE_RATE**: HackRF sample rate (default: 2000000, minimum: 2M)
- **BITRATE**: FSK bitrate (default: 1600, minimum for 2FSK Flex)
- **AMPLITUDE**: Software amplification (default: 127, range: -127 to 127)
- **FREQ_DEV**: Frequency deviation in Hz (default: 2400, Flex 2FSK is ±2400Hz = 4800Hz total)
- **TX_GAIN**: Hardware TX gain in dB (default: 0, range: 0-47)
- **DEFAULT_FREQUENCY**: Default frequency when not specified in HTTP requests (default: 931937500)

## Building

### Dependencies
```bash
# Install dependencies (Ubuntu/Debian)
make deps

# Or manually:
sudo apt-get install libhackrf-dev libssl-dev apache2-utils
```

### Compile
```bash
make clean && make
```

## Usage

```bash
./hackrf_http_server [OPTIONS]

OPTIONS:
  --help, -h     Show help message and exit
  --debug, -d    Enable debug mode (prints raw bytes, creates IQ file, skips transmission)
  --verbose, -v  Enable verbose output (comprehensive pipeline logging)
```

### Exit Codes (AWS Lambda Compatible)
- **0**: Success
- **1**: Invalid command line arguments
- **2**: Configuration errors
- **3**: Network setup errors (port binding failures)
- **4**: Authentication setup errors

## Usage Examples

### Starting the Server

```bash
# Start with verbose logging
./hackrf_http_server --verbose

# Start in debug mode (no transmission)
./hackrf_http_server --debug --verbose

# Start with environment variables
source vars.sh && ./hackrf_http_server --verbose

# Monitor with full verbose output
./hackrf_http_server --verbose 2>&1 | tee server.log
```

### Serial Protocol (TCP) Examples

Legacy protocol for backward compatibility. Send messages via TCP in format:
```
{CAPCODE}|{MESSAGE}|{FREQUENCY_HZ}
```

**Examples:**
```bash
# Using netcat
echo '001122334|Hello World|925516000' | nc localhost 16175

# Using netcat with timeout
echo '2223334|Emergency Alert|931937500' | timeout 5 nc localhost 16175

# Using telnet  
printf '001122334|Communicating like its the 90s|925516000' | telnet localhost 16175

# Multiple messages
echo '1122334|First message|925516000' | nc localhost 16175
echo '5555555|Second message|931937500' | nc localhost 16175
```

### HTTP Protocol (JSON API) Examples

Modern REST API with JSON format and HTTP basic authentication.

**Endpoint:** `POST http://localhost:16180/`

**Request Format:**
```json
{
    "capcode": 1122334,
    "message": "Hello World",
    "frequency": 925516000
}
```

**Notes:**
- The `capcode` field is optional (default: 37137)
- The `frequency` field is optional. If omitted, `DEFAULT_FREQUENCY` from config is used
- All requests require HTTP Basic Authentication
- Content-Type should be `application/json`

**Examples:**
```bash
# Complete message with all parameters
curl -X POST http://localhost:16180/ \
  -u admin:passw0rd \
  -H "Content-Type: application/json" \
  -d '{"capcode": 1122334, "message": "Hello from HTTP API", "frequency": 925516000}'

# Using frequency from DEFAULT_FREQUENCY config
curl -X POST http://localhost:16180/ \
  -u admin:passw0rd \
  -H "Content-Type: application/json" \
  -d '{"message": "Using default frequency and capcode"}'

# Minimal request (uses defaults for capcode and frequency)
curl -X POST http://localhost:16180/ \
  -u admin:passw0rd \
  -H "Content-Type: application/json" \
  -d '{"message": "Minimal message"}'

# Message with custom capcode only
curl -X POST http://localhost:16180/ \
  -u admin:passw0rd \
  -H "Content-Type: application/json" \
  -d '{"capcode": 5555555, "message": "Custom capcode message"}'

# Emergency message with high priority capcode
curl -X POST http://localhost:16180/ \
  -u admin:passw0rd \
  -H "Content-Type: application/json" \
  -d '{"capcode": 911911, "message": "EMERGENCY: System down", "frequency": 931937500}'

# Test authentication (should return 401)
curl -v -X POST http://localhost:16180/ \
  -u admin:wrongpass \
  -H "Content-Type: application/json" \
  -d '{"message": "This will fail"}'

# Test invalid JSON (should return 400)
curl -v -X POST http://localhost:16180/ \
  -u admin:passw0rd \
  -H "Content-Type: application/json" \
  -d '{"message": "Missing closing quote}'

# Test GET request (should return 405)
curl -v -X GET http://localhost:16180/ \
  -u admin:passw0rd
```

## Protocols

### Serial Protocol (TCP)

Legacy protocol for backward compatibility. Send messages via TCP in format:
```
{CAPCODE}|{MESSAGE}|{FREQUENCY_HZ}
```

### HTTP Response Codes

Standard HTTP response codes for seamless cloud integration:

- **200 OK**: Message transmitted successfully
- **400 Bad Request**: Invalid JSON format, missing required fields, or malformed data
- **401 Unauthorized**: Authentication required or credentials invalid
- **405 Method Not Allowed**: Only POST requests are supported
- **500 Internal Server Error**: Message processing or transmission failure

**Response Format:**
```json
// Success (200 OK)
{"status": "success", "message": "Message transmitted successfully"}

// Error (400/401/405/500)  
{"error": "Error description", "code": 400}
```

## Authentication

HTTP requests require HTTP Basic Authentication. User credentials are stored in the `./passwords` file using htpasswd format.

### Default Credentials

If the `passwords` file doesn't exist, it will be created automatically with default credentials:
- **Username:** `admin`
- **Password:** `passw0rd`

### Managing Users

Use the `htpasswd` tool to manage user accounts:

```bash
# Add or update a user with MD5 hash (compatible with most systems)
htpasswd -m passwords username

# Add or update a user with bcrypt hash (more secure, recommended)
htpasswd -B passwords username

# Create new passwords file and add first user
htpasswd -cm passwords admin

# Delete a user
htpasswd -D passwords username

# View current users (usernames only)
cut -d: -f1 passwords

# Verify a password
htpasswd -v passwords username

# List users
cut -d: -f1 passwords

# Change password for existing user
htpasswd -B passwords existinguser
```

### Authentication Examples

```bash
# Create/update user with bcrypt (recommended)
htpasswd -B passwords newuser

# Create/update user with MD5 (compatible)
htpasswd -m passwords newuser

# Verify password
htpasswd -v passwords admin

# Delete user
htpasswd -D passwords olduser

# List users
cut -d: -f1 passwords
```

### Security Notes

- The default password should be changed in production environments
- Use bcrypt hashing (`-B` flag) for better security when possible
- The passwords file should have restricted permissions: `chmod 600 passwords`
- Consider using HTTPS in production environments

## Verbose Logging

The `--verbose` flag enables comprehensive pipeline logging that shows every step of message processing:

### Verbose Output Sections

1. **Configuration Display**: Shows all loaded configuration parameters
2. **HTTP Client Connection**: Client IP, port, and raw HTTP request data
3. **Request Parsing**: Parsed HTTP method, path, headers, and body
4. **JSON Message Processing**: Shows parsed message data with defaults marked
5. **Message Processing Pipeline**:
   - Input parameter validation
   - Capcode validation (SHORT/LONG format detection)
   - FLEX encoding with complete hex dump display
   - Binary analysis (total bits, transmission time)
6. **HackRF Setup**: Device configuration and status
7. **FSK Modulation**: Detailed modulation parameters and sample generation
8. **File Output**: IQ file creation status (debug mode)
9. **RF Transmission**: Real-time transmission progress
10. **HTTP Response**: Response codes and body content

### Monitoring and Debugging Examples

```bash
# Monitor with full verbose output
./hackrf_http_server --verbose 2>&1 | tee server.log

# Debug mode with IQ file generation
./hackrf_http_server --debug --verbose
# Creates flexserver_output.iq for analysis

# Monitor HTTP responses
tail -f server.log | grep 'HTTP Response'

# Count successful transmissions
grep -c 'Message Processing Completed' server.log

# Monitor connection activity
tail -f server.log | grep -E '(Client connected|disconnected)'

# Watch for authentication failures
tail -f server.log | grep -i 'unauthorized\|authentication'

# Monitor FLEX encoding process
tail -f server.log | grep -A 10 'FLEX Encoding'
```

### Example Verbose Output
```
=== HTTP Client Connected ===
Client IP: 192.168.1.100
Client Port: 55916
Raw HTTP Request (245 bytes):
---
POST / HTTP/1.1
Host: localhost:16180
Authorization: Basic YWRtaW46cGFzc3cwcmQ=
Content-Type: application/json
Content-Length: 45

{"message": "Test message", "capcode": 12345}
---

=== JSON Message Processing ===
Message Data Received:
  Message: 'Test message'
  Capcode: 12345
  Frequency: 931937500 Hz (931.938 MHz) (default)
  Final Message: 'Test message'

=== Message Processing Started ===
...
```

## Advanced Features

### Port Configuration
- Both serial and HTTP ports can be independently enabled/disabled
- Set port to `0` in configuration to disable that protocol
- At least one port must be enabled for the server to start

### Emergency Message Resynchronization (EMR)
- Automatically sends EMR messages before the first transmission
- Sends EMR if no messages have been sent for more than 10 minutes  
- Ensures proper synchronization with paging receivers
- EMR transmission is logged in verbose mode

### Debug Mode
- Use `--debug` flag to enable debug mode
- Prints raw encoded bytes in hex format (complete output, no truncation)
- Creates `flexserver_output.iq` file for signal analysis with tools like GNU Radio
- Skips actual HackRF transmission for safe testing
- Shows EMR status without transmission

### Capcode Validation
- Supports both SHORT (18-bit) and LONG (32-bit) capcodes
- Automatic format detection and validation
- Detailed validation logging in verbose mode

### FLEX Encoding
- Uses TinyFlex library for FLEX protocol encoding
- Comprehensive error handling with detailed error codes
- Complete hex dump display of encoded data for analysis (no 24-line limit)

## Troubleshooting

### Common Issues

1. **"bind failed" error**
   - Port already in use by another process
   - Check with: `netstat -tlnp | grep :16175`
   - Change port in configuration or stop conflicting process

2. **"hackrf_open() failed"**
   - HackRF device not connected or recognized
   - Check USB connection and run: `hackrf_info`
   - May need to run with sudo or add user to plugdev group

3. **Authentication failures**
   - Verify credentials with: `htpasswd -v passwords username`
   - Check passwords file permissions and format
   - Ensure basic auth header is properly formatted
   - Use verbose mode to see authentication attempts

4. **"Invalid capcode" errors**
   - Capcode must be a valid numeric value
   - Check capcode format and range limits
   - Use verbose mode to see validation details

5. **JSON parsing errors**
   - Ensure valid JSON format
   - Check for missing quotes around string values
   - Verify Content-Type header is set to `application/json`

### Debugging Commands

```bash
# Test JSON parsing without transmission
./hackrf_http_server --debug --verbose

# Check raw IQ samples
./hackrf_http_server --debug
# Creates flexserver_output.iq file for analysis

# Monitor with verbose logging
./hackrf_http_server --verbose

# Test authentication
curl -v -X POST http://localhost:16180/ \
  -u admin:wrongpassword \
  -H "Content-Type: application/json" \
  -d '{"message": "test"}'

# Check port usage
netstat -tlnp | grep :16180

# Test HackRF device
hackrf_info
lsusb | grep HackRF

# Validate JSON syntax
echo '{"message": "test"}' | jq .

# Check file permissions
ls -la passwords
ls -la config.ini
```

### File Permissions

```bash
# Set proper permissions for passwords file
chmod 600 passwords

# Make executable
chmod +x hackrf_http_server

# Check HackRF device permissions
ls -la /dev/bus/usb/*/

# Add user to plugdev group for HackRF access
sudo usermod -a -G plugdev $USER
# Logout and login again for group membership to take effect
```

## Integration Examples

### AWS Lambda Integration
The server uses standard HTTP response codes making it perfect for AWS Lambda integration:

```python
import requests
import json

def lambda_handler(event, context):
    try:
        response = requests.post(
            'http://your-hackrf-server:16180/',
            auth=('admin', 'your-password'),
            headers={'Content-Type': 'application/json'},
            json={
                'message': event['message'],
                'capcode': event.get('capcode', 37137),
                'frequency': event.get('frequency')
            },
            timeout=30
        )

        if response.status_code == 200:
            return {
                'statusCode': 200,
                'body': json.dumps({'success': True, 'message': 'Transmitted'})
            }
        else:
            return {
                'statusCode': response.status_code,
                'body': response.text
            }

    except Exception as e:
        return {
            'statusCode': 500,
            'body': json.dumps({'error': str(e)})
        }
```

### Docker Integration
```dockerfile
FROM ubuntu:22.04

RUN apt-get update && apt-get install -y \
    libhackrf-dev \
    apache2-utils \
    && rm -rf /var/lib/apt/lists/*

COPY hackrf_http_server /usr/local/bin/
COPY config.ini /app/
COPY passwords /app/

WORKDIR /app
EXPOSE 16175 16180

CMD ["hackrf_http_server", "--verbose"]
```

### Python Client Example
```python
import requests
import json

class HackRFClient:
    def __init__(self, base_url, username, password):
        self.base_url = base_url
        self.auth = (username, password)
        self.headers = {'Content-Type': 'application/json'}

    def send_message(self, message, capcode=None, frequency=None):
        payload = {'message': message}
        if capcode:
            payload['capcode'] = capcode
        if frequency:
            payload['frequency'] = frequency

        try:
            response = requests.post(
                f'{self.base_url}/',
                auth=self.auth,
                headers=self.headers,
                json=payload,
                timeout=30
            )

            if response.status_code == 200:
                return {'success': True, 'data': response.json()}
            else:
                return {'success': False, 'error': response.text, 'code': response.status_code}

        except requests.exceptions.RequestException as e:
            return {'success': False, 'error': str(e)}

# Usage
client = HackRFClient('http://localhost:16180', 'admin', 'passw0rd')

# Send with all parameters
result = client.send_message('Emergency alert', capcode=911911, frequency=931937500)

# Send with defaults
result = client.send_message('Simple message')

print(result)
```

### Monitoring and Alerting
```bash
# Monitor server with verbose logging
./hackrf_http_server --verbose 2>&1 | tee server.log

# Extract transmission statistics
grep "Message Processing Completed" server.log | wc -l

# Monitor HTTP response codes
grep "HTTP Response sent" server.log | grep -o "Status: [0-9]*" | sort | uniq -c

# Monitor authentication failures
grep -i "unauthorized" server.log

# Monitor connection activity
grep -E "(connected|disconnected)" server.log

# Simple uptime monitoring
while true; do
    if curl -s -u admin:passw0rd -X POST http://localhost:16180/ \
       -H "Content-Type: application/json" \
       -d '{"message": "heartbeat"}' > /dev/null; then
        echo "$(date): Server OK"
    else
        echo "$(date): Server DOWN"
    fi
    sleep 60
done
```

## Complete Example Workflow

### 1. Setup and Configuration
```bash
# Create configuration file
cat > config.ini << EOF
BIND_ADDRESS=127.0.0.1
SERIAL_LISTEN_PORT=16175
HTTP_LISTEN_PORT=16180
SAMPLE_RATE=2000000
BITRATE=1600
AMPLITUDE=127
FREQ_DEV=2400
TX_GAIN=10
DEFAULT_FREQUENCY=931937500
EOF

# Create authentication
htpasswd -cb passwords admin mypassword
chmod 600 passwords

# Start server with verbose logging
./hackrf_http_server --verbose
```

### 2. Send Test Messages
```bash
# HTTP API with all parameters
curl -X POST http://localhost:16180/ \
  -u admin:mypassword \
  -H "Content-Type: application/json" \
  -d '{
    "capcode": 1122334,
    "message": "Emergency: System down",
    "frequency": 925516000
  }'

# HTTP API with defaults
curl -X POST http://localhost:16180/ \
  -u admin:mypassword \
  -H "Content-Type: application/json" \
  -d '{"message": "Using default capcode and frequency"}'

# TCP Serial protocol
echo '2223334|TCP protocol message|925516000' | nc localhost 16175
```

### 3. Monitor and Debug
The server will show detailed processing information including client connections, message parsing, FLEX encoding with complete hex dumps, HackRF setup, modulation parameters, and transmission status - providing complete visibility into the paging pipeline.

### 4. Production Deployment
```bash
# For production, consider:
# 1. Use config.ini instead of environment variables
# 2. Set appropriate TX_GAIN for your transmission requirements
# 3. Secure the passwords file (chmod 600)
# 4. Use proper firewall settings if binding to 0.0.0.0
# 5. Monitor logs for authentication failures and errors
# 6. Implement log rotation for verbose output
```

## License

This project is open source. Please ensure compliance with local regulations regarding radio transmission.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with appropriate tests
4. Submit a pull request with detailed description

For issues or feature requests, please use the project's issue tracker.

## Performance Tuning

### Optimizing for Different Use Cases

**High Throughput Setup:**
```ini
# config.ini for high message volume
SAMPLE_RATE=8000000
BITRATE=3200
AMPLITUDE=100
TX_GAIN=25
```

**Low Power Setup:**
```ini
# config.ini for battery/low power operation
AMPLITUDE=64
TX_GAIN=5
FREQ_DEV=1200
```

**Development/Testing Setup:**
```ini
# config.ini for safe testing
BIND_ADDRESS=127.0.0.1
SERIAL_LISTEN_PORT=0
HTTP_LISTEN_PORT=16180
# HTTP only, local access, no RF transmission with --debug
```

### System Requirements

- **Minimum**: 1GB RAM, 1 CPU core, USB 2.0
- **Recommended**: 2GB RAM, 2 CPU cores, USB 3.0
- **High Throughput**: 4GB RAM, 4 CPU cores, dedicated USB controller

### Frequency Planning

Common paging frequencies and considerations:

- **929-932 MHz**: Most common paging band in North America
- **152 MHz**: VHF paging (longer range, lower data rates)
- **454 MHz**: UHF paging (good compromise)
- **931.9375 MHz**: Default frequency used by this server

**Important**: Always check local regulations and ensure you have proper licensing before transmitting on any frequency.

## Advanced Configuration Examples

### Multi-User Production Setup

```bash
# Create multiple users with different access levels
htpasswd -cb passwords admin SecureAdminPass123
htpasswd -b passwords operator OperatorPass456
htpasswd -b passwords readonly ReadOnlyPass789

# Set restrictive permissions
chmod 600 passwords
chown hackrf:hackrf passwords

# Production config with security hardening
cat > config.ini << EOF
# Production Configuration
BIND_ADDRESS=0.0.0.0
SERIAL_LISTEN_PORT=0
HTTP_LISTEN_PORT=16180
SAMPLE_RATE=2000000
BITRATE=1600
AMPLITUDE=100
FREQ_DEV=2400
TX_GAIN=20
DEFAULT_FREQUENCY=931937500
EOF
```

### Systemd Service Integration

```bash
# Create systemd service file
sudo tee /etc/systemd/system/hackrf-server.service << EOF
[Unit]
Description=HackRF HTTP/TCP Paging Server
After=network.target
Wants=network.target

[Service]
Type=simple
User=hackrf
Group=hackrf
WorkingDirectory=/opt/hackrf-server
ExecStart=/opt/hackrf-server/hackrf_http_server --verbose
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
EOF

# Enable and start the service
sudo systemctl daemon-reload
sudo systemctl enable hackrf-server
sudo systemctl start hackrf-server

# Monitor service status
sudo systemctl status hackrf-server
sudo journalctl -u hackrf-server -f
```

### Load Balancing with Multiple HackRF Devices

For high-volume environments, you can run multiple instances:

```bash
# Instance 1 - Primary
./hackrf_http_server --verbose &
echo $! > hackrf1.pid

# Instance 2 - Secondary (different ports)
HTTP_LISTEN_PORT=16181 SERIAL_LISTEN_PORT=16176 \
./hackrf_http_server --verbose &
echo $! > hackrf2.pid

# Use nginx or HAProxy for load balancing between instances
```

## API Integration Patterns

### Webhook Integration

```python
# Flask webhook receiver that forwards to HackRF server
from flask import Flask, request, jsonify
import requests

app = Flask(__name__)

HACKRF_URL = 'http://localhost:16180/'
HACKRF_AUTH = ('admin', 'passw0rd')

@app.route('/webhook/alert', methods=['POST'])
def handle_alert():
    data = request.json

    # Transform webhook data to paging message
    message = f"ALERT: {data.get('title', 'Unknown')} - {data.get('description', '')}"
    capcode = data.get('priority', 1) * 1000000  # Priority-based capcode

    try:
        response = requests.post(
            HACKRF_URL,
            auth=HACKRF_AUTH,
            json={'message': message, 'capcode': capcode},
            timeout=10
        )

        if response.status_code == 200:
            return jsonify({'status': 'sent'})
        else:
            return jsonify({'error': 'failed to send'}), 500

    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
```

### Batch Message Processing

```python
# Send multiple messages efficiently
import requests
import json
from concurrent.futures import ThreadPoolExecutor
import time

class BatchPager:
    def __init__(self, server_url, username, password, max_workers=5):
        self.server_url = server_url
        self.auth = (username, password)
        self.headers = {'Content-Type': 'application/json'}
        self.max_workers = max_workers

    def send_single_message(self, message_data):
        try:
            response = requests.post(
                f'{self.server_url}/',
                auth=self.auth,
                headers=self.headers,
                json=message_data,
                timeout=30
            )
            return {
                'message': message_data,
                'success': response.status_code == 200,
                'response': response.text,
                'status_code': response.status_code
            }
        except Exception as e:
            return {
                'message': message_data,
                'success': False,
                'error': str(e)
            }

    def send_batch(self, messages, delay_between_messages=0.1):
        results = []

        with ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            futures = []

            for message in messages:
                future = executor.submit(self.send_single_message, message)
                futures.append(future)

                # Add delay to prevent overwhelming the server
                if delay_between_messages > 0:
                    time.sleep(delay_between_messages)

            # Collect results
            for future in futures:
                results.append(future.result())

        return results

# Usage example
pager = BatchPager('http://localhost:16180', 'admin', 'passw0rd')

messages = [
    {'message': 'System maintenance starting', 'capcode': 1000001},
    {'message': 'Database backup in progress', 'capcode': 1000002},
    {'message': 'Maintenance completed successfully', 'capcode': 1000003}
]

results = pager.send_batch(messages)

# Print results
for result in results:
    if result['success']:
        print(f"✓ Sent: {result['message']['message']}")
    else:
        print(f"✗ Failed: {result['message']['message']} - {result.get('error', result.get('response'))}")
```

## Security Best Practices

### Securing the Server

1. **Network Security**
   ```bash
   # Firewall rules (UFW example)
   sudo ufw allow from 192.168.1.0/24 to any port 16180
   sudo ufw deny 16180

   # Or for specific IPs only
   sudo ufw allow from 192.168.1.100 to any port 16180
   sudo ufw allow from 192.168.1.101 to any port 16180
   ```

2. **Authentication Hardening**
   ```bash
   # Use strong passwords
   htpasswd -B passwords admin  # Will prompt for password

   # Regular password rotation
   htpasswd -B passwords admin NewStrongPassword123

   # Remove default accounts
   htpasswd -D passwords admin  # After creating new admin account
   ```

3. **HTTPS with Reverse Proxy**
   ```nginx
   # nginx configuration for HTTPS termination
   server {
       listen 443 ssl http2;
       server_name paging.yourcompany.com;

       ssl_certificate /path/to/certificate.crt;
       ssl_certificate_key /path/to/private.key;

       location / {
           proxy_pass http://127.0.0.1:16180;
           proxy_set_header Host $host;
           proxy_set_header X-Real-IP $remote_addr;
           proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
           proxy_set_header X-Forwarded-Proto $scheme;
       }
   }
   ```

4. **Rate Limiting**
   ```bash
   # Using fail2ban to prevent brute force attacks
   sudo tee /etc/fail2ban/jail.d/hackrf-server.conf << EOF
   [hackrf-server]
   enabled = true
   port = 16180
   filter = hackrf-server
   logpath = /var/log/hackrf-server.log
   maxretry = 5
   bantime = 3600
   EOF

   # Create filter
   sudo tee /etc/fail2ban/filter.d/hackrf-server.conf << EOF
   [Definition]
   failregex = HTTP Response sent:\s+Status: 401
   ignoreregex =
   EOF
   ```

## Maintenance and Monitoring

### Log Management

```bash
# Log rotation setup
sudo tee /etc/logrotate.d/hackrf-server << EOF
/var/log/hackrf-server.log {
    daily
    rotate 7
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
EOF

# Manual log rotation
sudo logrotate -f /etc/logrotate.d/hackrf-server
```

### Health Monitoring

```bash
#!/bin/bash
# health-check.sh - Monitor server health

HACKRF_URL="http://localhost:16180"
AUTH="admin:passw0rd"
LOG_FILE="/var/log/hackrf-health.log"

check_health() {
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    # Test basic connectivity
    if curl -s -u "$AUTH" -X POST "$HACKRF_URL" \
       -H "Content-Type: application/json" \
       -d '{"message": "health-check"}' > /dev/null 2>&1; then
        echo "$timestamp: OK - Server responding" >> "$LOG_FILE"
        return 0
    else
        echo "$timestamp: ERROR - Server not responding" >> "$LOG_FILE"
        return 1
    fi
}

# Run health check
if ! check_health; then
    # Send alert (example using email)
    echo "HackRF server health check failed at $(date)" | \
        mail -s "HackRF Server Alert" admin@yourcompany.com

    # Try to restart service (if running as root)
    # systemctl restart hackrf-server
fi
```

### Performance Monitoring

```bash
#!/bin/bash
# monitor-performance.sh - Monitor server performance

LOG_FILE="/var/log/hackrf-server.log"
STATS_FILE="/var/log/hackrf-stats.log"

# Count messages processed in last hour
MESSAGES_LAST_HOUR=$(grep "Message Processing Completed" "$LOG_FILE" | \
    grep "$(date -d '1 hour ago' '+%Y-%m-%d %H')" | wc -l)

# Count authentication failures
AUTH_FAILURES=$(grep -i "unauthorized" "$LOG_FILE" | \
    grep "$(date '+%Y-%m-%d')" | wc -l)

# Count HTTP vs TCP usage
HTTP_REQUESTS=$(grep "HTTP client connected" "$LOG_FILE" | \
    grep "$(date '+%Y-%m-%d')" | wc -l)

TCP_REQUESTS=$(grep "Serial TCP client connected" "$LOG_FILE" | \
    grep "$(date '+%Y-%m-%d')" | wc -l)

# Log statistics
echo "$(date '+%Y-%m-%d %H:%M:%S'): Messages: $MESSAGES_LAST_HOUR/hr, Auth Failures: $AUTH_FAILURES, HTTP: $HTTP_REQUESTS, TCP: $TCP_REQUESTS" >> "$STATS_FILE"
```

## Troubleshooting Advanced Issues

### Memory and CPU Usage

```bash
# Monitor resource usage
top -p $(pgrep hackrf_http_server)

# Memory usage analysis
ps aux | grep hackrf_http_server

# Check for memory leaks
valgrind --tool=memcheck --leak-check=full ./hackrf_http_server --debug

# Profile CPU usage
perf record -g ./hackrf_http_server --verbose
perf report
```

### Network Troubleshooting

```bash
# Check port binding
ss -tlnp | grep hackrf

# Monitor network connections
netstat -an | grep :16180

# Test network connectivity
telnet localhost 16180

# Check firewall rules
sudo iptables -L -n | grep 16180
sudo ufw status verbose
```

### HackRF Device Issues

```bash
# Check HackRF device detection
hackrf_info

# Test HackRF functionality
hackrf_debug --help

# Check USB connection
lsusb | grep -i hackrf
dmesg | grep -i hackrf

# Reset HackRF device
hackrf_spiflash -R

# Check device permissions
ls -la /dev/bus/usb/*/

# Add user to required groups
sudo usermod -a -G plugdev,dialout $USER
```

### Common Error Solutions

**Error: "hackrf_start_tx() failed"**
```bash
# Solution 1: Check device connection
hackrf_info

# Solution 2: Reset device
hackrf_spiflash -R

# Solution 3: Check permissions
sudo ./hackrf_http_server --verbose
```

**Error: "bind failed"**
```bash
# Find process using port
sudo lsof -i :16180

# Kill conflicting process
sudo kill -9 <PID>

# Or change port in config
sed -i 's/HTTP_LISTEN_PORT=16180/HTTP_LISTEN_PORT=16181/' config.ini
```

**Error: "Invalid JSON format"**
```bash
# Validate JSON syntax
echo '{"message": "test"}' | jq .

# Check for common JSON errors
curl -v -X POST http://localhost:16180/ \
  -u admin:passw0rd \
  -H "Content-Type: application/json" \
  -d '{"message": "test"}'  # Missing closing quote would cause error
```

This comprehensive guide should help you successfully deploy, configure, and maintain the HackRF HTTP/TCP server in various environments, from development to production.

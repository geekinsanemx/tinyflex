# HackRF HTTP/TCP Server

A dual-protocol FLEX paging server for HackRF that supports both legacy TCP serial protocol and modern HTTP JSON API with authentication.

## Configuration

The server reads configuration from `config.txt` (preferred) or environment variables as fallback.

### config.txt
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
  --verbose, -v  Enable verbose output (detailed transmission info)
```

## Protocols

### Serial Protocol (TCP)

Legacy protocol for backward compatibility. Send messages via TCP in format:
```
{CAPCODE}|{MESSAGE}|{FREQUENCY_HZ}
```

**Examples:**
```bash
# Using netcat
echo '001122334|Hello World|925516000' | nc localhost 16175

# Using telnet  
printf '001122334|Communicating like its the 90s|925516000' | telnet localhost 16175
```

### HTTP Protocol (JSON API)

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
- The `frequency` field is optional. If omitted, `DEFAULT_FREQUENCY` from config is used
- All requests require HTTP Basic Authentication
- Content-Type should be `application/json`

**Examples:**
```bash
# Using curl with authentication
curl -X POST http://localhost:16180/ \
  -u admin:passw0rd \
  -H "Content-Type: application/json" \
  -d '{"capcode": 1122334, "message": "Hello from HTTP API", "frequency": 925516000}'

# Using frequency from DEFAULT_FREQUENCY config
curl -X POST http://localhost:16180/ \
  -u admin:passw0rd \
  -H "Content-Type: application/json" \
  -d '{"capcode": 1122334, "message": "Using default frequency"}'
```

**Response Format:**
```json
// Success (200 OK)
{"status": "success", "message": "Message sent successfully"}

// Error (400/401/500)  
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
```

### Security Notes

- The default password should be changed in production environments
- Use bcrypt hashing (`-B` flag) for better security when possible
- The passwords file should have restricted permissions: `chmod 600 passwords`
- Consider using HTTPS in production environments

## Features

### Port Configuration
- Both serial and HTTP ports can be independently enabled/disabled
- Set port to `0` in configuration to disable that protocol
- At least one port must be enabled for the server to start

### Emergency Message Resynchronization (EMR)
- Automatically sends EMR messages before the first transmission
- Sends EMR if no messages have been sent for more than 10 minutes  
- Ensures proper synchronization with paging receivers

### Debug Mode
- Use `--debug` flag to enable debug mode
- Prints raw encoded bytes
- Creates `flexserver_output.iq` file for signal analysis
- Skips actual HackRF transmission

### Verbose Mode
- Use `--verbose` flag for detailed transmission information
- Shows configuration on startup
- Displays detailed connection and processing information

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

4. **"Invalid capcode" errors**
   - Capcode must be a valid numeric value
   - Check capcode format and range limits

### File Permissions

```bash
# Set proper permissions for passwords file
chmod 600 passwords

# Make executable
chmod +x hackrf_http_server
```

## Examples

### Complete HTTP API Example

```bash
# 1. Start server with verbose output
./hackrf_http_server --verbose

# 2. In another terminal, send a message
curl -X POST http://localhost:16180/ \
  -u admin:passw0rd \
  -H "Content-Type: application/json" \
  -d '{
    "capcode": 1122334,
    "message": "Test message from HTTP API",
    "frequency": 925516000
  }'

# 3. Expected response
{"status": "success", "message": "Message sent successfully"}
```

### Mixed Protocol Usage

You can use both protocols simultaneously:

```bash
# Terminal 1: Start server
./hackrf_http_server --verbose

# Terminal 2: Send via HTTP
curl -X POST http://localhost:16180/ -u admin:passw0rd \
  -H "Content-Type: application/json" \
  -d '{"capcode": 1111111, "message": "HTTP message"}'

# Terminal 3: Send via TCP
echo '2222222|TCP message|925516000' | nc localhost 16175
```

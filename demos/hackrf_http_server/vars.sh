#!/bin/bash
# Example environment variables file for hackrf_http_server
# Usage: source vars.sh && ./hackrf_http_server

export BIND_ADDRESS="127.0.0.1"
export SERIAL_LISTEN_PORT="16175"  # Set to 0 to disable serial TCP protocol
export HTTP_LISTEN_PORT="16180"    # Set to 0 to disable HTTP JSON API
export SAMPLE_RATE="2000000"
export BITRATE="1600"
export AMPLITUDE="127"
export FREQ_DEV="2400"
export TX_GAIN="0"
export DEFAULT_FREQUENCY="931937500"

echo "Environment variables set for HackRF HTTP/TCP Server"
echo "BIND_ADDRESS: $BIND_ADDRESS"
echo "SERIAL_LISTEN_PORT: $SERIAL_LISTEN_PORT"
echo "HTTP_LISTEN_PORT: $HTTP_LISTEN_PORT"
echo "DEFAULT_FREQUENCY: $DEFAULT_FREQUENCY"
echo ""
echo "You can now run: ./hackrf_http_server"
echo ""
echo "Serial protocol example:"
echo "  echo '001122334|Hello World|925516000' | nc localhost $SERIAL_LISTEN_PORT"
echo ""
echo "HTTP API example:"
echo "  curl -X POST http://localhost:$HTTP_LISTEN_PORT/ -u admin:passw0rd \\"
echo "    -H 'Content-Type: application/json' \\"
echo "    -d '{\"capcode\": 1122334, \"message\": \"Hello World\", \"frequency\": 925516000}'"

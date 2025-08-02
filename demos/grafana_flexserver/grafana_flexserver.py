#!/usr/bin/env python3
"""
Grafana Alertmanager to HackRF FLEX Server Bridge
================================================

This service receives Grafana alertmanager webhook notifications and forwards
them to the HackRF HTTP server for FLEX paging transmission.

Features:
- Receives Grafana webhook alerts via REST API
- Parses multiple alerts from single JSON payload
- Extracts capcode and frequency from alert labels
- Prioritizes message content: summary > description > message
- HTTPS support with SSL certificates
- Comprehensive logging and error handling
- Systemd service integration
- Environment variable configuration

Author: Generated for HackRF FLEX Paging System
"""

import os
import sys
import json
import logging
import requests
import ssl
from datetime import datetime
from typing import List, Dict, Any, Optional, Tuple
from flask import Flask, request, jsonify
from werkzeug.serving import WSGIRequestHandler

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(sys.stdout),
        logging.FileHandler('/var/log/grafana_flexserver.log', mode='a')
    ]
)
logger = logging.getLogger('grafana_flexserver')

class GrafanaFlexServer:
    def __init__(self):
        """Initialize the Grafana FLEX Server with configuration from environment variables."""

        # Load configuration from environment variables
        self.hackrf_url = os.getenv('HACKRF_SERVER_URL', 'http://127.0.0.1:16180')
        self.hackrf_username = os.getenv('HACKRF_USERNAME', 'admin')
        self.hackrf_password = os.getenv('HACKRF_PASSWORD', 'passw0rd')

        # Flask server configuration
        self.bind_host = os.getenv('BIND_HOST', '0.0.0.0')
        self.bind_port = int(os.getenv('BIND_PORT', '8080'))

        # HTTPS/SSL configuration
        self.ssl_cert = os.getenv('SSL_CERT_PATH')
        self.ssl_key = os.getenv('SSL_KEY_PATH')
        self.ssl_enabled = bool(self.ssl_cert and self.ssl_key)

        # Default values for HackRF
        self.default_capcode = int(os.getenv('DEFAULT_CAPCODE', '37137'))
        self.default_frequency = int(os.getenv('DEFAULT_FREQUENCY', '931937500'))

        # Request timeout
        self.request_timeout = int(os.getenv('REQUEST_TIMEOUT', '30'))

        # Debug mode for detailed logging
        self.debug_mode = os.getenv('DEBUG_MODE', 'false').lower() in ('true', '1', 'yes')

        # Logging configuration
        log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
        logger.setLevel(getattr(logging, log_level, logging.INFO))

        if self.debug_mode:
            logger.setLevel(logging.DEBUG)

        # Initialize Flask app
        self.app = Flask(__name__)
        self.setup_routes()

        logger.info("Grafana FLEX Server initialized")
        logger.info(f"HackRF Server: {self.hackrf_url}")
        logger.info(f"Bind Address: {self.bind_host}:{self.bind_port}")
        logger.info(f"HTTPS Enabled: {self.ssl_enabled}")
        logger.info(f"Debug Mode: {self.debug_mode}")
        logger.info(f"Default Capcode: {self.default_capcode}")
        logger.info(f"Default Frequency: {self.default_frequency}")

    def setup_routes(self):
        """Setup Flask routes for the webhook service."""

        @self.app.route('/health', methods=['GET'])
        def health_check():
            """Health check endpoint."""
            return jsonify({
                'status': 'healthy',
                'timestamp': datetime.now().isoformat(),
                'hackrf_server': self.hackrf_url
            })

        @self.app.route('/api/v1/alerts', methods=['POST'])
        def webhook_handler():
            """Main webhook handler for Grafana alerts."""
            return self.handle_webhook()

        @self.app.route('/', methods=['POST'])
        def root_webhook_handler():
            """Alternative webhook endpoint at root path."""
            return self.handle_webhook()

        @self.app.errorhandler(404)
        def not_found(error):
            return jsonify({'error': 'Endpoint not found'}), 404

        @self.app.errorhandler(500)
        def internal_error(error):
            logger.error(f"Internal server error: {error}")
            return jsonify({'error': 'Internal server error'}), 500

    def handle_webhook(self) -> Tuple[Dict[str, Any], int]:
        """
        Handle incoming Grafana webhook requests.

        Returns:
            Tuple of (response_dict, status_code)
        """
        try:
            # Log incoming request
            client_ip = request.environ.get('HTTP_X_FORWARDED_FOR', request.remote_addr)
            logger.info(f"Received webhook from {client_ip}")

            if self.debug_mode:
                logger.debug(f"Request method: {request.method}")
                logger.debug(f"Request path: {request.path}")
                logger.debug(f"Request headers: {dict(request.headers)}")
                logger.debug(f"Request content type: {request.content_type}")
                logger.debug(f"Request content length: {request.content_length}")

            # Validate content type
            if not request.is_json:
                logger.warning("Invalid content type, expected application/json")
                return {'error': 'Content-Type must be application/json'}, 400

            # Parse JSON payload
            try:
                alerts_data = request.get_json()
                if self.debug_mode:
                    logger.debug(f"Raw webhook payload: {json.dumps(alerts_data, indent=2)}")
            except Exception as e:
                logger.error(f"JSON parsing error: {e}")
                return {'error': 'Invalid JSON payload'}, 400

            if not isinstance(alerts_data, list):
                logger.warning("Expected JSON array of alerts")
                return {'error': 'Expected JSON array of alerts'}, 400

            logger.info(f"Processing {len(alerts_data)} alerts")

            # Process each alert
            results = []
            success_count = 0
            error_count = 0

            for i, alert in enumerate(alerts_data):
                try:
                    result = self.process_alert(alert, i + 1)
                    results.append(result)

                    if result['success']:
                        success_count += 1
                    else:
                        error_count += 1

                except Exception as e:
                    logger.error(f"Error processing alert {i + 1}: {e}")
                    results.append({
                        'alert_index': i + 1,
                        'success': False,
                        'error': str(e)
                    })
                    error_count += 1

            # Prepare response
            response = {
                'status': 'completed',
                'total_alerts': len(alerts_data),
                'successful': success_count,
                'failed': error_count,
                'results': results,
                'timestamp': datetime.now().isoformat()
            }

            logger.info(f"Webhook processing completed: {success_count} successful, {error_count} failed")

            # Return appropriate status code
            if error_count == 0:
                return response, 200
            elif success_count > 0:
                return response, 207  # Multi-status
            else:
                return response, 500

        except Exception as e:
            logger.error(f"Webhook handler error: {e}")
            return {'error': 'Internal processing error', 'details': str(e)}, 500

    def process_alert(self, alert: Dict[str, Any], alert_index: int) -> Dict[str, Any]:
        """
        Process a single Grafana alert and send it to HackRF server.

        Args:
            alert: Alert dictionary from Grafana
            alert_index: Index of alert in the batch

        Returns:
            Dictionary with processing result
        """
        try:
            if self.debug_mode:
                logger.debug(f"Processing alert {alert_index}: {json.dumps(alert, indent=2)}")

            # Extract alert information
            labels = alert.get('labels', {})
            annotations = alert.get('annotations', {})

            # Get alert status (firing, resolved, etc.)
            # Determine alert status based on endsAt field
            # If endsAt is "0001-01-01T00:00:00Z" it means FIRING, otherwise RESOLVED
            ends_at = alert.get('endsAt', '')
            if ends_at == "0001-01-01T00:00:00Z":
                status = "FIRING"
            else:
                status = "RESOLVED"

            logger.debug(f"Alert {alert_index} endsAt: {ends_at} -> status: {status}")
            
            # Get alert name
            alert_name = labels.get('alertname', 'Unknown Alert')

            # Extract capcode from labels (optional) - use default if not found
            capcode = self.default_capcode
            for key in ['capcode', 'pager_capcode', 'flex_capcode']:
                if key in labels:
                    try:
                        capcode = int(labels[key])
                        logger.debug(f"Found capcode in {key}: {capcode}")
                        break
                    except (ValueError, TypeError):
                        logger.warning(f"Invalid capcode value in {key}: {labels[key]}, using default")

            # Extract frequency from labels (optional) - use default if not found
            frequency = self.default_frequency
            for key in ['frequency', 'pager_frequency', 'flex_frequency']:
                if key in labels:
                    try:
                        frequency = int(labels[key])
                        logger.debug(f"Found frequency in {key}: {frequency}")
                        break
                    except (ValueError, TypeError):
                        logger.warning(f"Invalid frequency value in {key}: {labels[key]}, using default")

            # Get message content with priority: summary > description > message
            message_content = None
            for key in ['summary', 'description', 'message']:
                if key in annotations and annotations[key]:
                    message_content = str(annotations[key]).strip()
                    logger.debug(f"Found message content in {key}: {message_content}")
                    break

            # If no message content found, use alert name
            if not message_content:
                message_content = "Alert triggered"
                logger.debug("No message content found, using default")

            # Format final message: "alertName: message"
            final_message = f"[{status}] {alert_name}: {message_content}"

            # ALWAYS construct payload with all three required fields
            hackrf_payload = {
                'capcode': capcode,
                'message': final_message,
                'frequency': frequency
            }

            logger.info(f"Alert {alert_index}: '{alert_name}' -> Sending to HackRF: capcode={capcode}, frequency={frequency}, message='{final_message[:50]}{'...' if len(final_message) > 50 else ''}'")

            if self.debug_mode:
                logger.debug(f"Complete HackRF payload: {json.dumps(hackrf_payload, indent=2)}")

            # Send to HackRF server
            success, response_data = self.send_to_hackrf(hackrf_payload)

            return {
                'alert_index': alert_index,
                'alert_name': alert_name,
                'message': final_message,
                'capcode': capcode,
                'frequency': frequency,
                'success': success,
                'hackrf_response': response_data
            }

        except Exception as e:
            logger.error(f"Error processing alert {alert_index}: {e}")
            return {
                'alert_index': alert_index,
                'success': False,
                'error': str(e)
            }

    def send_to_hackrf(self, payload: Dict[str, Any]) -> Tuple[bool, Dict[str, Any]]:
        """
        Send message payload to HackRF HTTP server.

        Args:
            payload: Message payload for HackRF server

        Returns:
            Tuple of (success_boolean, response_data)
        """
        try:
            # Prepare request
            url = f"{self.hackrf_url.rstrip('/')}/"
            auth = (self.hackrf_username, self.hackrf_password)
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'GrafanaFlexServer/1.0'
            }

            # Convert payload to JSON string
            json_payload = json.dumps(payload)

            if self.debug_mode:
                logger.debug(f"=== HackRF Request Debug ===")
                logger.debug(f"URL: {url}")
                logger.debug(f"Method: POST")
                logger.debug(f"Headers: {json.dumps(headers, indent=2)}")
                logger.debug(f"Auth: {self.hackrf_username}:{'*' * len(self.hackrf_password)}")
                logger.debug(f"JSON Payload: {json_payload}")
                logger.debug(f"Payload size: {len(json_payload)} bytes")
                logger.debug(f"Payload type: {type(json_payload)}")

                # Validate JSON is properly formatted
                try:
                    parsed_back = json.loads(json_payload)
                    logger.debug(f"JSON validation: SUCCESS")
                    logger.debug(f"Parsed back: {json.dumps(parsed_back, indent=2)}")
                except Exception as json_test_error:
                    logger.error(f"JSON validation: FAILED - {json_test_error}")

                logger.debug(f"=== End HackRF Request Debug ===")

            logger.debug(f"Sending to HackRF: POST {url}")

            # Send request with explicit JSON conversion
            response = requests.post(
                url,
                auth=auth,
                headers=headers,
                data=json_payload,  # Use data= with explicit JSON string
                timeout=self.request_timeout,
                verify=True  # Verify SSL certificates
            )

            if self.debug_mode:
                logger.debug(f"=== HackRF Response Debug ===")
                logger.debug(f"Status Code: {response.status_code}")
                logger.debug(f"Response Headers: {dict(response.headers)}")
                logger.debug(f"Response Text: {response.text}")
                logger.debug(f"Response Content Length: {len(response.text)}")
                logger.debug(f"=== End HackRF Response Debug ===")

            # Parse response
            try:
                response_data = response.json()
            except Exception as json_error:
                logger.warning(f"Failed to parse JSON response: {json_error}")
                response_data = {'raw_response': response.text}

            # Check success
            if response.status_code == 200:
                logger.info(f"Successfully sent to HackRF: {payload['message'][:50]}{'...' if len(payload['message']) > 50 else ''}")
                return True, response_data
            else:
                logger.error(f"HackRF server error {response.status_code}: {response_data}")
                return False, {
                    'error': f'HTTP {response.status_code}',
                    'details': response_data
                }

        except requests.exceptions.Timeout:
            error_msg = f"Timeout connecting to HackRF server after {self.request_timeout}s"
            logger.error(error_msg)
            return False, {'error': 'timeout', 'details': error_msg}

        except requests.exceptions.ConnectionError as e:
            error_msg = f"Connection error to HackRF server: {e}"
            logger.error(error_msg)
            return False, {'error': 'connection_error', 'details': error_msg}

        except Exception as e:
            error_msg = f"Unexpected error sending to HackRF: {e}"
            logger.error(error_msg)
            return False, {'error': 'unexpected_error', 'details': error_msg}

    def run(self):
        """Run the Flask server."""
        try:
            logger.info("Starting Grafana FLEX Server...")

            # Prepare SSL context if HTTPS is enabled
            ssl_context = None
            if self.ssl_enabled:
                if not os.path.isfile(self.ssl_cert):
                    logger.error(f"SSL certificate file not found: {self.ssl_cert}")
                    sys.exit(1)

                if not os.path.isfile(self.ssl_key):
                    logger.error(f"SSL key file not found: {self.ssl_key}")
                    sys.exit(1)

                ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
                ssl_context.load_cert_chain(self.ssl_cert, self.ssl_key)
                logger.info(f"HTTPS enabled with certificate: {self.ssl_cert}")

            # Custom request handler for better logging
            class CustomRequestHandler(WSGIRequestHandler):
                def log_request(self, code='-', size='-'):
                    if code != 200:
                        logger.info(f"{self.address_string()} - {self.command} {self.path} - {code}")

            # Run server
            self.app.run(
                host=self.bind_host,
                port=self.bind_port,
                ssl_context=ssl_context,
                request_handler=CustomRequestHandler,
                threaded=True,
                debug=False
            )

        except Exception as e:
            logger.error(f"Failed to start server: {e}")
            sys.exit(1)


def load_environment_file(env_file_path: str):
    """Load environment variables from file."""
    if os.path.isfile(env_file_path):
        logger.info(f"Loading environment variables from {env_file_path}")
        with open(env_file_path, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#') and '=' in line:
                    key, value = line.split('=', 1)
                    # Remove quotes if present
                    value = value.strip('"\'')
                    os.environ[key] = value
                    logger.debug(f"Loaded env var: {key}")
    else:
        logger.info(f"Environment file not found: {env_file_path}")


def main():
    """Main entry point."""
    try:
        # Load environment file if exists
        env_file = '/etc/default/grafana_flexserver'
        load_environment_file(env_file)

        # Create and run server
        server = GrafanaFlexServer()
        server.run()

    except KeyboardInterrupt:
        logger.info("Server stopped by user")
        sys.exit(0)
    except Exception as e:
        logger.error(f"Fatal error: {e}")
        sys.exit(1)


if __name__ == '__main__':
    main()

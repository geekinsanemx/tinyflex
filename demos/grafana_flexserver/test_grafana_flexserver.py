#!/usr/bin/env python3
"""
Debug Test Script for HackRF HTTP Server
========================================

This script helps debug communication issues between the Grafana FlexServer
and the HackRF HTTP Server by sending various test requests and analyzing responses.
"""

import json
import requests
import base64
import sys
from typing import Dict, Any

def test_hackrf_server(url: str = "http://127.0.0.1:16180",
                      username: str = "admin",
                      password: str = "passw0rd",
                      verbose: bool = True):
    """Test the HackRF HTTP server with various payloads."""

    print("=" * 60)
    print("HackRF HTTP Server Debug Test")
    print("=" * 60)
    print(f"Target URL: {url}")
    print(f"Username: {username}")
    print(f"Password: {'*' * len(password)}")
    print()

    # Test cases
    test_cases = [
        {
            "name": "Valid Complete Message",
            "payload": {
                "capcode": 37137,
                "message": "Test message from debug script",
                "frequency": 931937500
            }
        },
        {
            "name": "Minimal Message (only required field)",
            "payload": {
                "message": "Minimal test message"
            }
        },
        {
            "name": "Message with Custom Capcode",
            "payload": {
                "capcode": 1122334,
                "message": "Custom capcode test"
            }
        },
        {
            "name": "Empty Message (should fail)",
            "payload": {
                "capcode": 37137,
                "message": "",
                "frequency": 931937500
            }
        },
        {
            "name": "Missing Message Field (should fail)",
            "payload": {
                "capcode": 37137,
                "frequency": 931937500
            }
        },
        {
            "name": "Invalid JSON (should fail)",
            "payload": "invalid json string",
            "raw_data": True
        }
    ]

    # Run tests
    for i, test_case in enumerate(test_cases, 1):
        print(f"Test {i}: {test_case['name']}")
        print("-" * 40)

        try:
            # Prepare request
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'HackRFDebugTest/1.0'
            }

            auth = (username, password)

            # Prepare payload
            if test_case.get('raw_data'):
                data = test_case['payload']
                print(f"Raw Data: {data}")
            else:
                data = json.dumps(test_case['payload'])
                print(f"JSON Payload: {data}")

            print(f"Payload Length: {len(data)} bytes")
            print(f"Headers: {json.dumps(headers, indent=2)}")

            # Make request
            print("Sending request...")
            response = requests.post(
                url,
                auth=auth,
                headers=headers,
                data=data,
                timeout=10
            )

            print(f"Response Status: {response.status_code}")
            print(f"Response Headers: {dict(response.headers)}")
            print(f"Response Body: {response.text}")

            # Try to parse JSON response
            try:
                response_json = response.json()
                print(f"Parsed Response: {json.dumps(response_json, indent=2)}")
            except:
                print("Response is not valid JSON")

            if response.status_code == 200:
                print("✅ SUCCESS")
            else:
                print("❌ FAILED")

        except Exception as e:
            print(f"❌ ERROR: {e}")

        print()

def test_authentication(url: str = "http://127.0.0.1:16180"):
    """Test authentication scenarios."""

    print("=" * 60)
    print("Authentication Test")
    print("=" * 60)

    auth_tests = [
        {
            "name": "Valid Authentication",
            "username": "admin",
            "password": "passw0rd"
        },
        {
            "name": "Invalid Username",
            "username": "invalid",
            "password": "passw0rd"
        },
        {
            "name": "Invalid Password",
            "username": "admin",
            "password": "invalid"
        },
        {
            "name": "No Authentication",
            "username": None,
            "password": None
        }
    ]

    test_payload = {
        "message": "Auth test message"
    }

    for i, test in enumerate(auth_tests, 1):
        print(f"Auth Test {i}: {test['name']}")
        print("-" * 30)

        try:
            headers = {
                'Content-Type': 'application/json',
                'User-Agent': 'HackRFAuthTest/1.0'
            }

            auth = None
            if test['username'] and test['password']:
                auth = (test['username'], test['password'])
                print(f"Using auth: {test['username']}:{'*' * len(test['password'])}")
            else:
                print("No authentication")

            response = requests.post(
                url,
                auth=auth,
                headers=headers,
                data=json.dumps(test_payload),
                timeout=10
            )

            print(f"Status: {response.status_code}")
            print(f"Response: {response.text}")

            if response.status_code in [200, 401]:
                print("✅ Expected response")
            else:
                print("❌ Unexpected response")

        except Exception as e:
            print(f"❌ ERROR: {e}")

        print()

def test_grafana_webhook_simulation():
    """Simulate a Grafana webhook payload."""

    print("=" * 60)
    print("Grafana Webhook Simulation Test")
    print("=" * 60)

    # Simulate what the Python server would send to HackRF
    grafana_alert = {
        "labels": {
            "alertname": "TestAlert",
            "severity": "warning",
            "instance": "localhost:9090"
        },
        "annotations": {
            "summary": "This is a test alert summary",
            "description": "Test alert description with more details"
        }
    }

    # What the Python server should extract and send
    extracted_payload = {
        "capcode": 37137,  # default
        "message": "TestAlert: This is a test alert summary",  # alertname + summary
        "frequency": 931937500  # default
    }

    print("Original Grafana Alert:")
    print(json.dumps(grafana_alert, indent=2))
    print()
    print("Extracted HackRF Payload:")
    print(json.dumps(extracted_payload, indent=2))
    print()

    # Test the extracted payload
    test_hackrf_server(payload_override=extracted_payload)

def main():
    """Main test function."""
    if len(sys.argv) > 1:
        url = sys.argv[1]
    else:
        url = "http://127.0.0.1:16180"

    print("HackRF HTTP Server Debug Tool")
    print("============================")
    print()

    # Run all tests
    test_hackrf_server(url)
    test_authentication(url)
    test_grafana_webhook_simulation()

    print("=" * 60)
    print("Debug Tests Complete")
    print("=" * 60)
    print()
    print("If tests are failing:")
    print("1. Check that hackrf_http_server is running with --verbose")
    print("2. Verify the URL and credentials")
    print("3. Check the server logs for detailed error messages")
    print("4. Try running hackrf_http_server with --debug to skip RF transmission")

if __name__ == "__main__":
    main()

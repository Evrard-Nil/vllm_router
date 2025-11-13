#!/usr/bin/env python3
"""
Test script for URL-based service discovery.
This script creates a mock discovery server and tests the URLBasedServiceDiscovery.
"""

import json
import threading
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Dict

# Mock discovery data that matches the expected format
MOCK_DISCOVERY_DATA = {
    "nearai/gpt-oss-120b": {
        "count": 2,
        "endpoints": ["154.57.34.78:8002", "160.72.54.254:8001"],
    },
    "phala/qwen-2.5-7b-instruct": {
        "count": 1,
        "endpoints": ["redpill:phala/qwen-2.5-7b-instruct"],
    },
    "Qwen/Qwen3-30B-A3B-Instruct-2507": {
        "count": 3,
        "endpoints": ["154.57.34.78:8001", "160.72.54.254:8003", "160.72.54.254:8000"],
    },
}


class MockDiscoveryHandler(BaseHTTPRequestHandler):
    """Mock HTTP server that returns discovery data."""

    def do_GET(self):
        if self.path == "/discovery":
            self.send_response(200)
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(MOCK_DISCOVERY_DATA).encode())
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        # Suppress log messages
        pass


def start_mock_server(port: int = 8999) -> HTTPServer:
    """Start a mock discovery server."""
    server = HTTPServer(("localhost", port), MockDiscoveryHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    print(f"Mock discovery server started on port {port}")
    return server


def test_url_discovery():
    """Test the URL-based service discovery."""
    import sys
    import os

    # Add the current directory to Python path
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

    from service_discovery import URLBasedServiceDiscovery, ServiceDiscoveryType
    from unittest.mock import Mock

    # Start mock server
    server = start_mock_server()

    try:
        # Create a mock app
        mock_app = Mock()
        mock_app.state = Mock()
        mock_app.state.event_loop = Mock()

        # Create URL-based service discovery
        discovery = URLBasedServiceDiscovery(
            app=mock_app,
            discovery_url="http://localhost:8999/discovery",
            refresh_interval=5,  # Refresh every 5 seconds for testing
        )

        # Wait for initial discovery
        time.sleep(2)

        # Get endpoint info
        endpoints = discovery.get_endpoint_info()

        print(f"Discovered {len(endpoints)} endpoints:")
        for endpoint in endpoints:
            print(f"  - URL: {endpoint.url}")
            print(f"    Models: {endpoint.model_names}")
            print(f"    Label: {endpoint.model_label}")
            print()

        # Verify we got the expected endpoints
        expected_endpoints = {
            "http://154.57.34.78:8002": ["nearai/gpt-oss-120b"],
            "http://160.72.54.254:8001": ["nearai/gpt-oss-120b"],
            "http://redpill:phala/qwen-2.5-7b-instruct": ["phala/qwen-2.5-7b-instruct"],
            "http://154.57.34.78:8001": ["Qwen/Qwen3-30B-A3B-Instruct-2507"],
            "http://160.72.54.254:8003": ["Qwen/Qwen3-30B-A3B-Instruct-2507"],
            "http://160.72.54.254:8000": ["Qwen/Qwen3-30B-A3B-Instruct-2507"],
        }

        # Check if we got all expected endpoints
        actual_endpoints = {ep.url: ep.model_names for ep in endpoints}

        print("Expected endpoints:")
        for url, models in expected_endpoints.items():
            print(f"  - {url}: {models}")

        print("\nActual endpoints:")
        for url, models in actual_endpoints.items():
            print(f"  - {url}: {models}")

        # Verify match
        if actual_endpoints == expected_endpoints:
            print("\n✅ Test PASSED: All endpoints discovered correctly!")
        else:
            print("\n❌ Test FAILED: Endpoints don't match expected")
            print(
                f"Missing: {set(expected_endpoints.keys()) - set(actual_endpoints.keys())}"
            )
            print(
                f"Extra: {set(actual_endpoints.keys()) - set(expected_endpoints.keys())}"
            )

        # Test health check
        health = discovery.get_health()
        print(f"Service discovery health: {'✅ Healthy' if health else '❌ Unhealthy'}")

        # Close discovery
        discovery.close()

    except Exception as e:
        print(f"❌ Test FAILED with exception: {e}")
        import traceback

        traceback.print_exc()

    finally:
        server.shutdown()
        print("\nMock server stopped")


if __name__ == "__main__":
    test_url_discovery()

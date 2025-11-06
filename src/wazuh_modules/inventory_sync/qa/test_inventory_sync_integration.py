#!/usr/bin/env python3
"""
Integration Tests for Wazuh Inventory Sync Module
Tests the inventory_sync module using the Wazuh agent protocol with FlatBuffers.
"""
import json
import os
import pytest
import subprocess
import time
import docker
import requests
import logging
from pathlib import Path
from typing import Dict, List, Any, Optional
from jsonschema import validate, ValidationError

# Import the agent controller from the script provided
from wazuh_agent_controller import WazuhAgent
from flatbuffers_manager import create_message, parse_message, get_schema

# Global OpenSearch URL
GLOBAL_URL = 'localhost:9200'

def init_opensearch(low_resources=False):
    """
    Initialize OpenSearch container for testing.

    Args:
        low_resources: If True, configure for low resource usage

    Returns:
        Docker client instance
    """
    client = docker.from_env()
    env_vars = {
        'discovery.type': 'single-node',
        'plugins.security.disabled': 'true',
        'OPENSEARCH_INITIAL_ADMIN_PASSWORD': 'WazuhTest99$'
    }

    if low_resources:
        env_vars['http.max_content_length'] = '4mb'

    # Check if container already exists
    try:
        existing_container = client.containers.get('opensearch-test')
        if existing_container.status == 'running':
            print("OpenSearch container already running")
            return client
        else:
            existing_container.remove()
    except docker.errors.NotFound:
        pass

    # Start new container
    client.containers.run(
        "opensearchproject/opensearch:latest",
        detach=True,
        ports={'9200/tcp': 9200},
        environment=env_vars,
        name='opensearch-test',
        stdout=True,
        stderr=True
    )

    # Wait for OpenSearch to be ready
    print("Waiting for OpenSearch to be ready...")
    while True:
        try:
            response = requests.get('http://' + GLOBAL_URL, timeout=5)
            if response.status_code == 200:
                print("OpenSearch is ready")
                break
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            pass
        time.sleep(1)

    return client


@pytest.fixture(scope='function')
def opensearch(request):
    """
    Pytest fixture for OpenSearch testing.
    """
    low_resources = getattr(request, 'param', False)
    client = init_opensearch(low_resources)
    yield client
    # Stop all containers
    for container in client.containers.list():
        container.stop()
    client.containers.prune()


class InventorySyncIntegrationTester:
    def __init__(self, manager_address: str = "127.0.0.1",
                 manager_port: int = 1514,
                 registration_port: int = 1515,
                 test_data_dir: str = "test_data",
                 expected_data_dir: str = "expected_data"):
        """
        Initialize the integration tester.

        Args:
            manager_address: Wazuh manager IP address
            manager_port: Port for communication with manager
            registration_port: Port for agent registration
            test_data_dir: Directory containing test data JSON files
            expected_data_dir: Directory containing expected result JSON files
        """
        self.manager_address = manager_address
        self.manager_port = manager_port
        self.registration_port = registration_port

        # Convert to Path objects for easier handling
        self.test_data_dir = Path(test_data_dir)
        self.expected_data_dir = Path(expected_data_dir)

        # Initialize agent and FlatBuffers manager
        self.agent = None
        self.schema = get_schema()

        # Test session tracking - support multiple sessions
        self.sessions = {}  # Dictionary to store multiple sessions by ID
        self.test_results = []

        # Ensure directories exist
        self.test_data_dir.mkdir(exist_ok=True)
        self.expected_data_dir.mkdir(exist_ok=True)

        # OpenSearch client for testing
        self.opensearch_client = None

    def setup_opensearch(self, low_resources=False):
        """
        Setup OpenSearch for testing.

        Args:
            low_resources: If True, configure for low resource usage
        """
        self.opensearch_client = init_opensearch(low_resources)

        # Clear all test indices before starting
        if not self.clear_all_indices():
            print("⚠️ Warning: Failed to clear indices, continuing anyway")

        # Create inventory_sync index
        if not self.create_inventory_sync_index():
            raise Exception("Failed to create inventory_sync index")

    def check_opensearch_health(self):
        """
        Check OpenSearch health status.

        Returns:
            bool: True if OpenSearch is healthy
        """
        try:
            url = 'http://' + GLOBAL_URL + '/_cluster/health'
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                health_data = response.json()
                return health_data['status'] in ['green', 'yellow']
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            pass
        return False

    def clear_all_indices(self):
        """
        Clear all indices except system indices.

        Returns:
            bool: True if indices were cleared successfully, False otherwise
        """
        try:
            # Get all indices
            url = 'http://' + GLOBAL_URL + '/_cat/indices?format=json'
            response = requests.get(url, timeout=5)
            if response.status_code != 200:
                print(f"❌ Failed to get indices: {response.status_code}")
                return False

            indices = response.json()
            indices_to_delete = []

            # Filter out system indices (those starting with .)
            for index in indices:
                index_name = index.get('index', '')
                if not index_name.startswith('.') and index_name not in ['security', 'opendistro_security']:
                    indices_to_delete.append(index_name)

            if indices_to_delete:
                # Delete each index
                for index_name in indices_to_delete:
                    delete_url = f'http://{GLOBAL_URL}/{index_name}'
                    delete_response = requests.delete(delete_url, timeout=10)
                    if delete_response.status_code != 200:
                        print(f"⚠️ Failed to delete index {index_name}: {delete_response.status_code}")
            else:
                pass  # No test indices to clear

            return True

        except Exception as e:
            print(f"❌ Error clearing indices: {e}")
            return False

    def create_inventory_sync_index(self):
        """
        Create the inventory_sync index in OpenSearch.

        Returns:
            bool: True if index was created successfully, False otherwise
        """
        try:
            url = 'http://' + GLOBAL_URL + '/inventory_sync'

            # Check if index already exists
            check_response = requests.head(url, timeout=5)
            if check_response.status_code == 200:
                return True

            # Create index with mapping
            index_mapping = {
                "mappings": {
                    "properties": {
                        "id": {"type": "keyword"},
                        "index": {"type": "keyword"},
                        "operation": {"type": "keyword"},
                        "seq": {"type": "long"},
                        "session": {"type": "long"},
                        "data": {"type": "object", "enabled": True},
                        "timestamp": {"type": "date"}
                    }
                },
                "settings": {
                    "number_of_shards": 1,
                    "number_of_replicas": 0
                }
            }

            response = requests.put(url, json=index_mapping, timeout=10)
            if response.status_code == 200:
                return True
            else:
                print(f"❌ Failed to create inventory_sync index: {response.status_code} - {response.text}")
                return False

        except Exception as e:
            print(f"❌ Error creating inventory_sync index: {e}")
            return False

    def check_opensearch_indices(self, test_name: str):
        """
        Check OpenSearch indices after test execution.

        Args:
            test_name: Name of the test for logging
        """
        try:
            url = 'http://' + GLOBAL_URL + '/_cat/indices'
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                indices = response.text.strip()
                if indices:
                    print(f"📊 OpenSearch indices for {test_name}:")
                    print(indices)

                    # Check for any inventory-related indices
                    if 'inventory' in indices.lower() or 'wazuh' in indices.lower():
                        print(f"✅ Inventory indices found in OpenSearch for {test_name}")
                    else:
                        print(f"ℹ️ No inventory indices found in OpenSearch for {test_name}")
                else:
                    print(f"ℹ️ No indices found in OpenSearch for {test_name}")
        except Exception as e:
            print(f"⚠️ Could not check OpenSearch indices for {test_name}: {e}")

    def setup_agent(self, agent_id: Optional[str] = None,
                   agent_name: Optional[str] = None,
                   agent_key: Optional[str] = None) -> None:
        """
        Setup and register a Wazuh agent for testing.

        Args:
            agent_id: Existing agent ID (if using existing agent)
            agent_name: Agent name
            agent_key: Agent key
        """
        self.agent = WazuhAgent(
            manager_address=self.manager_address,
            registration_address=self.manager_address,
            enable_flatbuffer=True
        )

        if agent_id:
            # Use existing agent
            self.agent.load_existing_agent(agent_id, agent_name, agent_key)
        else:
            # Register new agent
            self.agent.register_agent(agent_name)
            self.agent.create_encryption_key()

    def load_test_data(self, test_name: str) -> Dict[str, Any]:
        """
        Load test data from JSON file.

        Args:
            test_name: Name of the test (without .json extension)

        Returns:
            Test data dictionary
        """
        test_file = self.test_data_dir / f"{test_name}.json"
        if not test_file.exists():
            raise FileNotFoundError(f"Test data file not found: {test_file}")

        with open(test_file, 'r') as f:
            return json.load(f)

    def load_expected_data(self, test_name: str) -> Dict[str, Any]:
        """
        Load expected results from JSON file.

        Args:
            test_name: Name of the test (without .json extension)

        Returns:
            Expected results dictionary
        """
        expected_file = self.expected_data_dir / f"{test_name}.json"
        if not expected_file.exists():
            raise FileNotFoundError(f"Expected data file not found: {expected_file}")

        with open(expected_file, 'r') as f:
            return json.load(f)

    def send_inventory_sync_message(self, message_type: str, data: Dict[str, Any],
                                  session_from_start: str = None, timeout: float = 5.0) -> Dict[str, Any]:
        """
        Send a message to the inventory_sync module.

        Args:
            message_type: Type of message (start, data, end, etc.)
            data: Message data dictionary
            session_from_start: Session ID to use from a previous start response

        Returns:
            Response from the module
        """
        import time

        if self.agent is None:
            raise RuntimeError("Agent not initialized. Call setup_agent() first.")

        # Create the payload in the format expected by inventory_sync
        payload_data = {
            "type": message_type,
            **data
        }

        # Handle session based on message type
        if message_type == "start":
            # Start messages don't include session in the request
            pass
        elif session_from_start and session_from_start in self.sessions:
            # Use session from a previous start response
            session_value = self.sessions[session_from_start]
            # Ensure session is an integer for FlatBuffers
            if isinstance(session_value, str):
                payload_data["session"] = int(session_value)
            else:
                payload_data["session"] = session_value
        elif "session" in data:
            # Use session provided in data (legacy support)
            payload_data["session"] = data["session"]

        # Create FlatBuffer payload
        payload = f"s:inventory_sync:{json.dumps(payload_data)}"



        try:
            # Send payload to manager using the agent controller
            # For start and end messages, expect a response
            expect_response = message_type in ["start", "end"]

            # Record start time for timeout calculation
            start_time = time.time()
            response_data = self.agent.send_payload(payload, expect_response=expect_response, timeout=timeout)
            response_time = time.time() - start_time

            # Check timeout if response was expected
            if expect_response and response_time > timeout:
                print(f"⚠️  Response timeout: {response_time:.2f}s > {timeout}s")

            # Create response object
            response = {
                "type": "response",
                "message_type": message_type,
                "session": payload_data.get("session"),
                "status": "sent",
                "timestamp": time.time(),
                "response": response_data,  # Store server response for validation
                "response_time": response_time,
                "timeout_exceeded": expect_response and response_time > timeout
            }

            # Extract session from start response
            if message_type == "start" and response_data:
                session_id = self._extract_session_from_response(response_data)
                if session_id:
                    response["extracted_session"] = session_id
                else:
                    print(f"⚠️  No session found in manager response")

            return response

        except Exception as e:
            print(f"❌ Error sending message: {e}")
            return {
                "type": "error",
                "message_type": message_type,
                "error": str(e),
                "timestamp": time.time()
            }

    def _extract_session_from_response(self, response_data):
        """Extract session ID from manager response."""
        try:
            if not response_data:
                return None

            # Check different response formats
            if isinstance(response_data, dict):
                # Handle new response structure from agent controller
                if response_data.get('type') == 'startup_response':
                    session = response_data.get('session')
                    return session
                elif response_data.get('type') == 'control_ack':
                    return None
                elif response_data.get('type') == 'raw_text':
                    # Try to extract session from raw text
                    raw_text = response_data.get('data', '')
                    import re
                    session_match = re.search(r'"session":\s*(\d+)', raw_text)
                    if session_match:
                        return session_match.group(1)
                elif response_data.get('type') == 'raw_binary':
                    # Try to parse the binary data as FlatBuffer
                    try:
                        raw_hex = response_data.get('raw_data', '')
                        if raw_hex:
                            binary_data = bytes.fromhex(raw_hex)
                            from flatbuffers_manager import parse_message
                            parsed_fb = parse_message(binary_data)
                            if isinstance(parsed_fb, dict):
                                session = parsed_fb.get('session')
                                if session:
                                    return str(session)
                    except Exception as e:
                        pass
                elif response_data.get('type') == 'flatbuffer':
                    fb_data = response_data.get('data', {})
                    if isinstance(fb_data, dict):
                        session = fb_data.get('session')
                        if session:
                            return session  # Keep as integer, don't convert to string
                elif response_data.get('type') == 'json':
                    json_data = response_data.get('data', {})
                    if isinstance(json_data, dict):
                        session = json_data.get('session')
                        if session:
                            return str(session)

                # JSON response
                if 'data' in response_data:
                    data = response_data['data']
                    if isinstance(data, dict):
                        # Look for session in various possible fields
                        session = (data.get('session') or
                                 data.get('session_id') or
                                 data.get('id'))
                        if session:
                            return str(session)

                # Direct session field
                session = response_data.get('session') or response_data.get('session_id')
                if session:
                    return str(session)

            # If response is a string, try to parse as JSON
            if isinstance(response_data, str):
                import json
                try:
                    parsed = json.loads(response_data)
                    return self._extract_session_from_response(parsed)
                except:
                    # Try to extract session from plain text
                    import re
                    session_match = re.search(r'"session":\s*(\d+)', response_data)
                    if session_match:
                        session = session_match.group(1)
                        return session

            return None

        except Exception as e:
            print(f"⚠️  Error extracting session: {e}")
            return None

    def execute_test_sequence(self, test_name: str) -> Dict[str, Any]:
        """
        Execute a complete test sequence from JSON file.

        Args:
            test_name: Name of the test (without .json extension)

        Returns:
            Test execution results
        """
        import time

        print(f"\n🧪 Executing test sequence: {test_name}")
        print("=" * 60)

        # Load test data
        test_data = self.load_test_data(test_name)
        expected_data = self.load_expected_data(test_name)

        # Initialize results
        results = {
            "test_name": test_name,
            "status": "running",
            "messages": [],
            "errors": [],
            "start_time": time.time()
        }

        try:
            # Clear sessions for this test
            self.sessions.clear()

            # Get messages to execute
            messages = test_data.get("messages", [])
            print(f"📋 Test: {test_data.get('description', test_name)}")
            print(f"📊 Messages to send: {len(messages)}")

            # Execute each message in sequence
            for i, message in enumerate(messages, 1):
                try:
                    # Extract message details
                    message_type = message["type"]
                    message_data = message["data"].copy()  # Copy to avoid modifying original
                    description = message.get("description", f"{message_type} message")

                    # Handle session management
                    session_from_start = None
                    if message.get("use_session_from_start"):
                        session_key = message["use_session_from_start"]
                        if isinstance(session_key, str) and session_key in self.sessions:
                            session_from_start = session_key
                        elif session_key is True and "default" in self.sessions:
                            session_from_start = "default"

                        if session_from_start and session_from_start in self.sessions:
                            session_value = self.sessions[session_from_start]
                            # Ensure session is an integer for FlatBuffers
                            if isinstance(session_value, str):
                                message_data["session"] = int(session_value)
                            else:
                                message_data["session"] = session_value

                    # Get timeout from expected data if available
                    timeout = 5.0  # Default timeout
                    expected_messages = expected_data.get("expected_messages", [])
                    if i-1 < len(expected_messages):
                        expected_msg = expected_messages[i-1]
                        expected_response = expected_msg.get("expected_response")
                        if expected_response and "timeout" in expected_response:
                            timeout = expected_response["timeout"]

                    # Send the message
                    response = self.send_inventory_sync_message(message_type, message_data, session_from_start, timeout)
                    results["messages"].append(response)

                    # Store session if this is a start message and we received one
                    if message_type == "start" and response.get("extracted_session"):
                        session_key = message.get("session_id", "default")
                        self.sessions[session_key] = response["extracted_session"]

                    # Add delay between messages if specified
                    delay = message.get("delay", 0)
                    if delay > 0:
                        import time
                        time.sleep(delay)

                except Exception as e:
                    error_msg = f"Failed to send message {i}: {str(e)}"
                    print(f"❌ {error_msg}")
                    results["errors"].append(error_msg)
                    continue

            # Mark as completed
            results["status"] = "completed"

        except Exception as e:
            results["status"] = "error"
            results["errors"].append(f"Test execution error: {str(e)}")
            print(f"\n💥 Test '{test_name}' ERROR: {str(e)}")

        import time
        results["end_time"] = time.time()
        results["duration"] = results["end_time"] - results["start_time"]

        # Validate results
        validation_results = self.validate_results(results, expected_data)
        results["validation"] = validation_results

        # Set the final status based on validation
        results["status"] = "passed" if validation_results["passed"] else "failed"

        # Print summary
        if validation_results["passed"]:
            print(f"\n✅ Test '{test_name}' PASSED")
        else:
            print(f"\n❌ Test '{test_name}' FAILED")
            for error in validation_results["errors"]:
                print(f"   - {error}")

        print(f"Test result: {'passed' if validation_results['passed'] else 'failed'}")
        print(f"Duration: {results['duration']:.2f}s")
        print(f"Messages sent: {len([m for m in results['messages'] if m.get('status') == 'sent'])}")

        return results

    def validate_results(self, actual_results: Dict[str, Any],
                        expected_results: Dict[str, Any]) -> Dict[str, Any]:
        """
        Validate actual results against expected results.

        Args:
            actual_results: Results from test execution
            expected_results: Expected results from JSON file

        Returns:
            Validation results dictionary
        """
        validation = {
            "passed": True,
            "errors": [],
            "warnings": []
        }

        try:
            # Check expected message count
            expected_count = expected_results.get("expected_message_count", 0)
            actual_count = len([m for m in actual_results["messages"] if m.get("status") == "sent"])

            if expected_count > 0 and actual_count != expected_count:
                validation["passed"] = False
                validation["errors"].append(f"Message count mismatch: expected {expected_count}, got {actual_count}")

            # Check for session consistency if required
            if expected_results.get("validate_session_consistency", False):
                sessions_used = set()
                for message in actual_results["messages"]:
                    if message.get("session"):
                        sessions_used.add(message["session"])

                if len(sessions_used) > 1:
                    validation["passed"] = False
                    validation["errors"].append(f"Session inconsistency: multiple sessions found {sessions_used}")

            # Check expected messages and their responses
            expected_messages = expected_results.get("expected_messages", [])
            for i, expected_msg in enumerate(expected_messages):
                if i < len(actual_results["messages"]):
                    actual_msg = actual_results["messages"][i]
                    expected_status = expected_msg.get("expected_status", "sent")

                    # Check message status
                    if actual_msg.get("status") != expected_status:
                        validation["passed"] = False
                        validation["errors"].append(f"Message {i+1} status mismatch: expected {expected_status}, got {actual_msg.get('status')}")

                    # Check server response
                    expected_response = expected_msg.get("expected_response")
                    actual_response = actual_msg.get("response")

                    if expected_response is None:
                        # No response expected (like for data messages)
                        if actual_response is not None:
                            validation["passed"] = False
                            validation["errors"].append(f"Message {i+1} ({expected_msg.get('type', 'unknown')}) should not have a response, but got: {actual_response}")
                    else:
                        # Response expected
                        if actual_response is None:
                            validation["passed"] = False
                            validation["errors"].append(f"Message {i+1} ({expected_msg.get('type', 'unknown')}) should have a response, but got none")
                        else:
                            # Validate response structure
                            response_validation = self._validate_response(actual_response, expected_response, i+1, actual_msg)
                            if not response_validation["passed"]:
                                validation["passed"] = False
                                validation["errors"].extend(response_validation["errors"])
                else:
                    validation["passed"] = False
                    validation["errors"].append(f"Missing expected message {i+1}")

            # Check for execution errors
            if actual_results.get("errors"):
                for error in actual_results["errors"]:
                    validation["errors"].append(error)
                validation["passed"] = False

        except Exception as e:
            validation["passed"] = False
            validation["errors"].append(f"Validation error: {str(e)}")

        return validation

    def _validate_response(self, actual_response: Dict[str, Any], expected_response: Dict[str, Any], message_index: int, actual_msg: Dict[str, Any] = None) -> Dict[str, Any]:
        """
        Validate actual response against expected response.

        Args:
            actual_response: Actual response from server
            expected_response: Expected response structure
            message_index: Index of the message for error reporting

        Returns:
            Validation results dictionary
        """
        validation = {
            "passed": True,
            "errors": []
        }

        try:
            # Check response type
            expected_type = expected_response.get("type")
            actual_type = actual_response.get("type")

            if expected_type and actual_type != expected_type:
                validation["passed"] = False
                validation["errors"].append(f"Message {message_index} response type mismatch: expected {expected_type}, got {actual_type}")

            # Check response data structure
            expected_data = expected_response.get("data")
            if expected_data:
                actual_data = actual_response.get("data")
                if not actual_data:
                    validation["passed"] = False
                    validation["errors"].append(f"Message {message_index} response missing data field")
                else:
                    # Validate data fields
                    for field, expected_value in expected_data.items():
                        if field not in actual_data:
                            validation["passed"] = False
                            validation["errors"].append(f"Message {message_index} response missing field '{field}'")
                        elif actual_data[field] != expected_value:
                            validation["passed"] = False
                            validation["errors"].append(f"Message {message_index} response field '{field}' mismatch: expected {expected_value}, got {actual_data[field]}")

            # Check if session validation is required
            if expected_response.get("validate_session", False):
                if "session" not in actual_response.get("data", {}):
                    validation["passed"] = False
                    validation["errors"].append(f"Message {message_index} response missing session field")
                elif not actual_response["data"]["session"]:
                    validation["passed"] = False
                    validation["errors"].append(f"Message {message_index} response has empty session field")

            # Check timeout if specified
            expected_timeout = expected_response.get("timeout")
            if expected_timeout and actual_msg:
                actual_timeout = actual_msg.get("timeout_exceeded", False)
                response_time = actual_msg.get("response_time", 0)

                if actual_timeout:
                    validation["passed"] = False
                    validation["errors"].append(f"Message {message_index} response timeout exceeded: {response_time:.2f}s > {expected_timeout}s")

        except Exception as e:
            validation["passed"] = False
            validation["errors"].append(f"Response validation error for message {message_index}: {str(e)}")

        return validation

    def run_all_tests(self) -> List[Dict[str, Any]]:
        """
        Discover and run all test files in the test_data directory.

        Returns:
            List of test results
        """
        test_files = list(self.test_data_dir.glob("*.json"))
        all_results = []

        print(f"🔍 Discovered {len(test_files)} test files")

        for test_file in test_files:
            test_name = test_file.stem
            try:
                print(f"\n🧪 Running test: {test_name}")
                result = self.execute_test_sequence(test_name)
                all_results.append(result)
            except Exception as e:
                print(f"❌ Test '{test_name}' failed with error: {e}")
                all_results.append({
                    "test_name": test_name,
                    "status": "error",
                    "error": str(e)
                })

        return all_results

    def print_test_summary(self, results: List[Dict[str, Any]]) -> None:
        """
        Print a summary of all test results.

        Args:
            results: List of test results
        """
        print(f"\n📊 Test Summary:")
        print("=" * 50)

        passed = 0
        failed = 0
        errors = 0

        for result in results:
            test_name = result.get("test_name", "Unknown")
            status = result.get("status", "unknown")
            validation = result.get("validation", {})

            if status == "error":
                print(f"💥 {test_name}: ERROR")
                errors += 1
            elif validation.get("passed", False):
                print(f"✅ {test_name}: PASSED")
                passed += 1
            else:
                print(f"❌ {test_name}: FAILED")
                failed += 1

        print(f"\nTotal tests: {len(results)}")
        print(f"✅ Passed: {passed}")
        print(f"❌ Failed: {failed}")
        print(f"💥 Errors: {errors}")

        if failed > 0 or errors > 0:
            print("⚠️  Some tests failed or had errors")
        else:
            print("🎉 All tests passed!")


# Pytest integration
@pytest.fixture
def inventory_sync_tester(opensearch):
    """Pytest fixture for inventory sync tester with OpenSearch."""
    tester = InventorySyncIntegrationTester()
    # Setup OpenSearch for all tests
    tester.setup_opensearch()
    yield tester
    # Cleanup if needed


def test_inventory_sync_basic_flow(inventory_sync_tester):
    """Test basic inventory sync flow."""
    tester = inventory_sync_tester

    # Verify OpenSearch is healthy
    assert tester.check_opensearch_health(), "OpenSearch is not healthy"

    tester.setup_agent()

    result = tester.execute_test_sequence("basic_flow")
    assert result["status"] == "completed"
    assert result["validation"]["passed"]

    # Wait for indexing to complete and check OpenSearch
    time.sleep(2)
    tester.check_opensearch_indices("basic_flow")


def test_inventory_sync_multiple_data_messages(inventory_sync_tester):
    """Test inventory sync with multiple data messages."""
    tester = inventory_sync_tester

    # Verify OpenSearch is healthy
    assert tester.check_opensearch_health(), "OpenSearch is not healthy"

    tester.setup_agent()

    result = tester.execute_test_sequence("multiple_data")
    assert result["status"] == "completed"
    assert result["validation"]["passed"]

    # Wait for indexing to complete and check OpenSearch
    time.sleep(2)
    tester.check_opensearch_indices("multiple_data")


def test_inventory_sync_error_handling(inventory_sync_tester):
    """Test inventory sync error handling."""
    tester = inventory_sync_tester

    # Verify OpenSearch is healthy
    assert tester.check_opensearch_health(), "OpenSearch is not healthy"

    tester.setup_agent()

    result = tester.execute_test_sequence("error_handling")
    assert result["status"] == "completed"
    # Note: Error handling tests may intentionally fail some validations

    # Wait for indexing to complete and check OpenSearch
    time.sleep(2)
    tester.check_opensearch_indices("error_handling")


def test_inventory_sync_session_management(inventory_sync_tester):
    """Test inventory sync session management."""
    tester = inventory_sync_tester

    # Verify OpenSearch is healthy
    assert tester.check_opensearch_health(), "OpenSearch is not healthy"

    tester.setup_agent()

    result = tester.execute_test_sequence("session_management")
    assert result["status"] == "completed"
    assert result["validation"]["passed"]

    # Wait for indexing to complete and check OpenSearch
    time.sleep(2)
    tester.check_opensearch_indices("session_management")





def test_inventory_sync_metadata_delta(inventory_sync_tester):
    """
    Test metadata delta synchronization flow.
    This test verifies that agent metadata is updated across all specified indices
    using the MetadataDelta mode without sending data messages.
    """
    result = inventory_sync_tester.execute_test_sequence("metadata_delta_flow")
    assert result["validation"]["passed"], f"Metadata delta test failed: {result['validation'].get('errors', [])}"

    # Wait for indexer to process updates
    time.sleep(2)

    # Verify documents were updated in OpenSearch
    inventory_sync_tester.check_opensearch_indices("metadata_delta_flow")


def test_inventory_sync_groups_delta(inventory_sync_tester):
    """
    Test groups delta synchronization flow.
    This test verifies that agent groups are updated across all specified indices
    using the GroupDelta mode without sending data messages.
    """
    result = inventory_sync_tester.execute_test_sequence("groups_delta_flow")
    assert result["validation"]["passed"], f"Groups delta test failed: {result['validation'].get('errors', [])}"

    # Wait for indexer to process updates
    time.sleep(2)

    # Verify documents were updated in OpenSearch
    inventory_sync_tester.check_opensearch_indices("groups_delta_flow")


@pytest.mark.parametrize('opensearch', [False], indirect=True)
def test_opensearch_health(opensearch):
    """Test OpenSearch health check."""
    url = 'http://' + GLOBAL_URL + '/_cluster/health'
    response = requests.get(url)
    assert response.status_code == 200
    assert response.json()['status'] in ['green', 'yellow']


if __name__ == "__main__":
    # Command line execution
    import argparse

    parser = argparse.ArgumentParser(description="Inventory Sync Integration Tests")
    parser.add_argument("--manager", default="127.0.0.1", help="Manager IP address")
    parser.add_argument("--port", type=int, default=1514, help="Manager port")
    parser.add_argument("--test", help="Specific test to run")
    parser.add_argument("--list-tests", action="store_true", help="List available tests")

    args = parser.parse_args()

    tester = InventorySyncIntegrationTester(
        manager_address=args.manager,
        manager_port=args.port
    )

    if args.list_tests:
        test_files = list(tester.test_data_dir.glob("*.json"))
        print("📋 Available Tests:")
        print("=" * 50)
        for test_file in test_files:
            try:
                test_data = tester.load_test_data(test_file.stem)
                description = test_data.get("description", "No description")
                print(f"✅ {test_file.stem}")
                print(f"   {description}")
                print()
            except Exception as e:
                print(f"❌ {test_file.stem}: Error loading - {e}")
        exit(0)

    try:
        # Setup OpenSearch for command line execution
        tester.setup_opensearch()

        # Verify OpenSearch is healthy
        if not tester.check_opensearch_health():
            print("❌ OpenSearch is not healthy. Please check if Docker is running and port 9200 is available.")
            exit(1)

        tester.setup_agent()

        if args.test:
            result = tester.execute_test_sequence(args.test)
            # Wait for indexing and check OpenSearch
            time.sleep(2)
            tester.check_opensearch_indices(args.test)
            exit(0 if result["validation"]["passed"] else 1)
        else:
            results = tester.run_all_tests()
            tester.print_test_summary(results)

            # Exit with error code if any tests failed
            failed_count = sum(1 for r in results if not r.get("validation", {}).get("passed", False))
            exit(0 if failed_count == 0 else 1)

    except Exception as e:
        print(f"❌ Error: {e}")
        exit(1)

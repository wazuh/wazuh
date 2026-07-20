#!/usr/bin/env python3
"""
Test Runner for Inventory Sync Integration Tests
Executes the integration tests for the inventory_sync module.
"""

import argparse
import sys
import os
import time
from pathlib import Path

# Add the current directory to Python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from test_inventory_sync_integration import InventorySyncIntegrationTester


def main():
    """Main function to run the integration tests."""
    parser = argparse.ArgumentParser(
        description="Inventory Sync Integration Test Runner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Run all tests
  python run_tests.py --manager 127.0.0.1

  # Run specific test
  python run_tests.py --manager 127.0.0.1 --test basic_flow

  # Use existing agent
  python run_tests.py --manager 127.0.0.1 --agent-id 001 --agent-name "test-agent"

  # Run with custom ports
  python run_tests.py --manager 127.0.0.1 --port 1514 --registration-port 1515
        """
    )
    
    parser.add_argument(
        "--manager", 
        default="127.0.0.1", 
        help="Wazuh manager IP address (default: 127.0.0.1)"
    )
    parser.add_argument(
        "--port", 
        type=int, 
        default=1514, 
        help="Wazuh manager communication port (default: 1514)"
    )
    parser.add_argument(
        "--registration-port", 
        type=int, 
        default=1515, 
        help="Wazuh manager registration port (default: 1515)"
    )
    parser.add_argument(
        "--test", 
        help="Run specific test (without .json extension)"
    )
    parser.add_argument(
        "--agent-id", 
        help="Use existing agent ID"
    )
    parser.add_argument(
        "--agent-name", 
        help="Agent name (optional if using existing agent)"
    )
    parser.add_argument(
        "--agent-key", 
        help="Agent key (optional if using existing agent)"
    )
    parser.add_argument(
        "--test-data-dir", 
        default="test_data", 
        help="Directory containing test data files (default: test_data)"
    )
    parser.add_argument(
        "--expected-data-dir", 
        default="expected_data", 
        help="Directory containing expected data files (default: expected_data)"
    )
    parser.add_argument(
        "--verbose", 
        "-v", 
        action="store_true", 
        help="Enable verbose output"
    )
    parser.add_argument(
        "--list-tests", 
        action="store_true", 
        help="List available tests and exit"
    )
    
    args = parser.parse_args()
    
    # Create tester instance
    tester = InventorySyncIntegrationTester(
        manager_address=args.manager,
        manager_port=args.port,
        registration_port=args.registration_port,
        test_data_dir=args.test_data_dir,
        expected_data_dir=args.expected_data_dir
    )
    
    # List available tests
    if args.list_tests:
        print("📋 Available Tests:")
        print("=" * 50)
        
        test_files = list(tester.test_data_dir.glob("*.json"))
        if not test_files:
            print("❌ No test files found in test_data directory")
            return 1
        
        for test_file in test_files:
            test_name = test_file.stem
            expected_file = tester.expected_data_dir / f"{test_name}.json"
            
            status = "✅" if expected_file.exists() else "⚠️"
            print(f"{status} {test_name}")
            
            # Try to read test description
            try:
                with open(test_file, 'r') as f:
                    import json
                    test_data = json.load(f)
                    description = test_data.get("description", "No description")
                    print(f"   {description}")
            except:
                print("   Error reading test description")
            
            if not expected_file.exists():
                print("   ⚠️  No expected data file found")
            
            print()
        
        return 0
    
    # Setup OpenSearch for command line execution
    try:
        print("🔧 Setting up OpenSearch...")
        tester.setup_opensearch()
        
        # Verify OpenSearch is healthy
        if not tester.check_opensearch_health():
            print("❌ OpenSearch is not healthy. Please check if Docker is running and port 9200 is available.")
            return 1
        print("✅ OpenSearch is healthy and ready")
    except Exception as e:
        print(f"❌ Failed to setup OpenSearch: {e}")
        return 1
    
    # Setup agent
    try:
        tester.setup_agent(args.agent_id, args.agent_name, args.agent_key)
    except Exception as e:
        print(f"❌ Failed to setup agent: {e}")
        return 1
    
    # Run tests
    try:
        if args.test:
            # Run specific test
            print(f"🧪 Running test: {args.test}")
            result = tester.execute_test_sequence(args.test)
            results = [result]
            
            # Wait for indexing and check OpenSearch
            print("⏳ Waiting for indexing to complete...")
            import time
            time.sleep(2)
            tester.check_opensearch_indices(args.test)
        else:
            # Run all tests
            results = tester.run_all_tests()
            
            # Check OpenSearch indices for all tests
            print("⏳ Checking OpenSearch indices for all tests...")
            import time
            time.sleep(2)
            tester.check_opensearch_indices("all_tests")
        
        # Print summary
        if args.verbose:
            print("\n📊 Detailed Results:")
            print("=" * 50)
            for result in results:
                print(f"\nTest: {result['test_name']}")
                print(f"Status: {result['status']}")
                print(f"Duration: {result['duration']:.2f}s")
                if result.get('errors'):
                    print("Errors:")
                    for error in result['errors']:
                        print(f"  - {error}")
        
        # Determine exit code
        all_passed = all(r["status"] == "passed" for r in results)
        exit_code = 0 if all_passed else 1
        
        if all_passed:
            print(f"\n✅ All tests passed! ({len(results)} tests)")
        else:
            failed_count = sum(1 for r in results if r["status"] != "passed")
            print(f"\n❌ {failed_count} test(s) failed out of {len(results)} total")
        
        return exit_code
        
    except Exception as e:
        print(f"❌ Test execution failed: {e}")
        return 1


if __name__ == "__main__":
    exit(main())

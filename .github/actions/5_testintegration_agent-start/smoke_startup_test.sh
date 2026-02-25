#!/bin/bash

log_error() {
    echo "Error: $1"
    exit 1
}

log_info() {
    echo "[INFO] $1"
}

log_success() {
    echo "[SUCCESS] $1"
}

set_utils(){
    if [ -n "$(command -v rpm)" ]; then
        install="rpm -ivh --ignorearch"
        check_package_status='rpm -q'
        package_extension="rpm"
        log_info "Detected RPM-based system"
    elif [ -n "$(command -v dpkg)" ]; then
        install="dpkg --install"
        check_package_status='dpkg-query -W'
        package_extension="deb"
        export DEBIAN_FRONTEND=noninteractive
        log_info "Detected DEB-based system"
    else
        log_error "Couldn't find type of system"
    fi
}

install_package(){
    local package_path=$1

    if [ -z "$package_path" ]; then
        log_error "No package found to install"
    fi

    if [ ! -f "$package_path" ]; then
        log_error "Package file not found: $package_path"
    fi

    log_info "Installing package: $package_path"

    if [ "$package_extension" == "deb" ]; then
        WAZUH_MANAGER="1.2.3.4" $install "$package_path" || apt-get install -f -y
    else
        WAZUH_MANAGER="1.2.3.4" $install "$package_path"
    fi

    # Verify installation
    if $check_package_status "wazuh-agent" >/dev/null 2>&1; then
        log_success "Package installed successfully"
    else
        log_error "Package installation verification failed"
    fi
}

test_daemons(){
    local daemons="wazuh-modulesd wazuh-logcollector wazuh-syscheckd wazuh-agentd wazuh-execd"

    log_info "Testing daemons with -t flag (configuration test)..."

    for daemon in $daemons; do
        log_info "Testing ${daemon}..."

        if ! /var/ossec/bin/${daemon} -t 2>&1 | tee -a /packages/daemon_tests.log; then
            log_error "${daemon} -t failed with exit code $?"
        fi

        log_success "${daemon} -t passed"
    done
}

start_agent(){
    log_info "Starting Wazuh agent..."

    if ! /var/ossec/bin/wazuh-control start 2>&1 | tee -a /packages/agent_start.log; then
        log_error "Failed to start Wazuh agent"
    fi

    log_success "Wazuh agent started"

    # Wait for agent to initialize
    log_info "Waiting for agent to initialize (10 seconds)..."
    sleep 10
}

verify_agent_running(){
    log_info "Verifying agent is running..."

    if ! /var/ossec/bin/wazuh-control status 2>&1 | tee /packages/agent_status.log; then
        log_error "Agent status check failed"
    fi

    log_success "Agent is running"
}

stop_agent(){
    log_info "Stopping Wazuh agent..."

    if ! /var/ossec/bin/wazuh-control stop 2>&1 | tee -a /packages/agent_stop.log; then
        log_error "Failed to stop Wazuh agent"
    fi

    log_success "Wazuh agent stopped successfully"
}

check_test_results(){
    log_info "=== Smoke Test Results Summary ==="

    # Check if all log files were created
    local all_tests_passed=true

    if [ ! -f /packages/daemon_tests.log ]; then
        log_error "Daemon tests log not found"
        all_tests_passed=false
    fi

    if [ ! -f /packages/agent_status.log ]; then
        log_error "Agent status log not found"
        all_tests_passed=false
    fi

    if [ "$all_tests_passed" = true ]; then
        log_success "All smoke tests passed successfully!"
        echo "---"
        echo "Test artifacts created in /packages/:"
        ls -lh /packages/*.log 2>/dev/null || true
        return 0
    else
        log_error "Some tests failed. Check logs in /packages/"
        return 1
    fi
}

main() {
    log_info "=== Wazuh Agent Startup Smoke Test ==="

    set_utils

    # Find the package
    package_name="/packages/$(ls /packages | grep "wazuh.*$package_extension$" | grep -Ev "dbg|debug|debuginfo" | head -n1)"

    if [ -z "$package_name" ] || [ "$package_name" == "/packages/" ]; then
        log_error "No suitable package found in /packages/"
    fi

    log_info "Found package: $package_name"

    # Run smoke test steps
    install_package "$package_name"
    test_daemons
    start_agent
    verify_agent_running
    stop_agent
    check_test_results

    log_success "=== Smoke test completed successfully ==="
}

main

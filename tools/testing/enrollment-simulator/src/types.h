#pragma once

#include "agent_config.h"

#include <string>
#include <chrono>
#include <atomic>

// Constants
constexpr int BUFFER_SIZE = 1024;
constexpr int PROGRESS_INTERVAL = 100;
constexpr int SSL_CONNECT_TIMEOUT_SEC = 30;

// Registration result structure
struct RegistrationResult {
    bool success;
    double response_time;  // in milliseconds
    AgentConfig config;
    std::string response;
};

// Global flag for Ctrl+C handling
extern std::atomic<bool> stop_simulation;

// Helper function to calculate elapsed time in milliseconds
double calculate_elapsed_time(const std::chrono::high_resolution_clock::time_point& start);

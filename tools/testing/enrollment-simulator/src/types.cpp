#include "types.h"
#include <chrono>
#include <algorithm>

// Global flag implementation
std::atomic<bool> stop_simulation(false);

// Helper function to calculate elapsed time in milliseconds
double calculate_elapsed_time(const std::chrono::high_resolution_clock::time_point& start) {
    auto end = std::chrono::high_resolution_clock::now();
    double elapsed = std::chrono::duration<double, std::milli>(end - start).count();
    return std::max(0.0, elapsed); // Ensure non-negative
}

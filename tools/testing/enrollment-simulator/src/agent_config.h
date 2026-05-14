#pragma once

#include <string>
#include <random>

// Delay range structure
struct DelayRange {
    int min;
    int max;

    DelayRange() : min(0), max(0) {}
    DelayRange(int value) : min(value), max(value) {}
    DelayRange(int min_val, int max_val);

    int get_random_value(std::mt19937& gen) const;
    static DelayRange parse(const std::string& str);
    std::string to_string() const;
};

// Agent configuration
struct AgentConfig {
    std::string name;
    std::string password;
    std::string version;
    std::string group;
    bool is_new;
    bool has_correct_password;
    bool is_modern_version;
    bool has_group;
};

#include "agent_config.h"
#include <stdexcept>
#include <random>

// DelayRange implementation
DelayRange::DelayRange(int min_val, int max_val) : min(min_val), max(max_val) {
    if (min_val > max_val) {
        throw std::invalid_argument("DelayRange: min cannot be greater than max");
    }
}

int DelayRange::get_random_value(std::mt19937& gen) const {
    if (min == max) return min;
    thread_local std::uniform_int_distribution<> dis;
    return dis(gen, std::uniform_int_distribution<>::param_type(min, max));
}

DelayRange DelayRange::parse(const std::string& str) {
    size_t dash_pos = str.find('-');
    if (dash_pos != std::string::npos) {
        int min = std::stoi(str.substr(0, dash_pos));
        int max = std::stoi(str.substr(dash_pos + 1));
        return DelayRange(min, max);
    } else {
        int value = std::stoi(str);
        return DelayRange(value);
    }
}

std::string DelayRange::to_string() const {
    if (min == max) {
        return std::to_string(min);
    } else {
        return std::to_string(min) + "-" + std::to_string(max);
    }
}

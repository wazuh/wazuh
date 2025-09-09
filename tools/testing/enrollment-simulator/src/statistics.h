#pragma once

#include "types.h"
#include <vector>
#include <functional>
#include <string>

class StatisticsManager {
private:
    std::vector<RegistrationResult> results;

    template<typename Predicate>
    void print_category_stats(const std::string& category, const std::string& true_label,
                             const std::string& false_label, Predicate pred);

public:
    void add_result(const RegistrationResult& result);
    void print_statistics(double total_time, int target_total);
    void clear();
    size_t size() const { return results.size(); }

    // Access to results for CSV export
    const std::vector<RegistrationResult>& get_results() const { return results; }
};

#include "statistics.h"
#include "agent_config.h"
#include <iostream>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <cmath>

void StatisticsManager::add_result(const RegistrationResult& result) {
    results.push_back(result);
}

void StatisticsManager::clear() {
    results.clear();
}

void StatisticsManager::print_statistics(double total_time, int target_total) {
    std::cout << "\n" << std::string(60, '=') << std::endl;
    if (stop_simulation) {
        std::cout << "SIMULATION RESULTS (PARTIAL - INTERRUPTED)" << std::endl;
    } else {
        std::cout << "SIMULATION RESULTS" << std::endl;
    }
    std::cout << std::string(60, '=') << std::endl;

    int total = results.size();
    if (total == 0) {
        std::cout << "\nNo registrations completed before interruption." << std::endl;
        return;
    }

    int successful = std::count_if(results.begin(), results.end(),
                                   [](const RegistrationResult& r) { return r.success; });
    int failed = total - successful;

    std::cout << "\nOverall Statistics:" << std::endl;
    std::cout << "  Target registrations: " << target_total << std::endl;
    std::cout << "  Completed registrations: " << total
              << " (" << std::fixed << std::setprecision(2)
              << (100.0 * total / target_total) << "% of target)" << std::endl;
    std::cout << "  Successful: " << successful
              << " (" << (100.0 * successful / total) << "%)" << std::endl;
    std::cout << "  Failed: " << failed
              << " (" << (100.0 * failed / total) << "%)" << std::endl;
    std::cout << "  Total time: " << total_time << " seconds" << std::endl;
    std::cout << "  Throughput: " << (total / total_time)
              << " registrations/second" << std::endl;

    // Response time statistics
    std::vector<double> response_times;
    for (const auto& r : results) {
        response_times.push_back(r.response_time);
    }

    if (!response_times.empty()) {
        std::sort(response_times.begin(), response_times.end());
        double min_time = response_times.front();
        double max_time = response_times.back();
        double mean_time = std::accumulate(response_times.begin(), response_times.end(), 0.0) / response_times.size();
        double median_time = response_times[response_times.size() / 2];

        std::cout << "\nResponse Time Statistics (ms):" << std::endl;
        std::cout << "  Min: " << min_time << std::endl;
        std::cout << "  Max: " << max_time << std::endl;
        std::cout << "  Mean: " << mean_time << std::endl;
        std::cout << "  Median: " << median_time << std::endl;

        if (response_times.size() > 1) {
            double sq_sum = 0;
            for (double time : response_times) {
                sq_sum += (time - mean_time) * (time - mean_time);
            }
            double stdev = std::sqrt(sq_sum / (response_times.size() - 1));
            std::cout << "  Std Dev: " << stdev << std::endl;
        }
    }

    // Statistics by category
    std::cout << "\n" << std::string(60, '-') << std::endl;
    std::cout << "Statistics by Category:" << std::endl;
    std::cout << std::string(60, '-') << std::endl;

    // New vs Repeated
    print_category_stats("Agent Type", "New agents", "Repeated agents",
                       [](const RegistrationResult& r) { return r.config.is_new; });

    // Password correctness
    print_category_stats("Password", "Correct password", "Incorrect password",
                       [](const RegistrationResult& r) { return r.config.has_correct_password; });

    // Version
    print_category_stats("Version", "Modern version (v4.15.0)", "Normal version (v4.12.0)",
                       [](const RegistrationResult& r) { return r.config.is_modern_version; });

    // Group
    print_category_stats("Group", "With group", "Without group",
                       [](const RegistrationResult& r) { return r.config.has_group; });

    std::cout << "\n" << std::string(60, '=') << std::endl;
}

template<typename Predicate>
void StatisticsManager::print_category_stats(const std::string& category, const std::string& true_label,
                                           const std::string& false_label, Predicate pred) {
    std::vector<RegistrationResult> true_results, false_results;

    for (const auto& r : results) {
        if (pred(r)) {
            true_results.push_back(r);
        } else {
            false_results.push_back(r);
        }
    }

    std::cout << "\n" << category << ":" << std::endl;

    if (!true_results.empty()) {
        int success = std::count_if(true_results.begin(), true_results.end(),
                                   [](const RegistrationResult& r) { return r.success; });
        double avg_time = 0;
        for (const auto& r : true_results) {
            avg_time += r.response_time;
        }
        avg_time /= true_results.size();

        std::cout << "  " << true_label << ": " << true_results.size()
                  << " (" << std::fixed << std::setprecision(2)
                  << (100.0 * true_results.size() / results.size()) << "%)" << std::endl;
        std::cout << "    Success rate: " << (100.0 * success / true_results.size()) << "%" << std::endl;
        std::cout << "    Avg response time: " << avg_time << " ms" << std::endl;
    }

    if (!false_results.empty()) {
        int success = std::count_if(false_results.begin(), false_results.end(),
                                   [](const RegistrationResult& r) { return r.success; });
        double avg_time = 0;
        for (const auto& r : false_results) {
            avg_time += r.response_time;
        }
        avg_time /= false_results.size();

        std::cout << "  " << false_label << ": " << false_results.size()
                  << " (" << std::fixed << std::setprecision(2)
                  << (100.0 * false_results.size() / results.size()) << "%)" << std::endl;
        std::cout << "    Success rate: " << (100.0 * success / false_results.size()) << "%" << std::endl;
        std::cout << "    Avg response time: " << avg_time << " ms" << std::endl;
    }
}

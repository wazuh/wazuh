#include "csv_exporter.h"
#include "agent_config.h"
#include <fstream>
#include <iostream>
#include <algorithm>
#include <numeric>
#include <iomanip>
#include <cmath>

void CSVExporter::write_csv_results(const std::vector<RegistrationResult>& results,
                                     const std::string& csv_file,
                                     double total_time,
                                     int target_total) {
    std::ofstream csv(csv_file);
    if (!csv.is_open()) {
        std::cerr << "Warning: Could not open CSV file: " << csv_file << std::endl;
        return;
    }

    // Calculate overall statistics
    int total = results.size();
    if (total == 0) {
        csv << "No results to report\n";
        csv.close();
        return;
    }

    int successful = std::count_if(results.begin(), results.end(),
                                   [](const RegistrationResult& r) { return r.success; });
    int failed = total - successful;

    // Calculate response time statistics
    std::vector<double> response_times;
    for (const auto& r : results) {
        response_times.push_back(r.response_time);
    }
    std::sort(response_times.begin(), response_times.end());

    double min_time = response_times.front();
    double max_time = response_times.back();
    double mean_time = std::accumulate(response_times.begin(), response_times.end(), 0.0) / response_times.size();
    double median_time = response_times[response_times.size() / 2];
    double stdev = 0;
    if (response_times.size() > 1) {
        double sq_sum = 0;
        for (double time : response_times) {
            sq_sum += (time - mean_time) * (time - mean_time);
        }
        stdev = std::sqrt(sq_sum / (response_times.size() - 1));
    }

    // Write CSV header and overall statistics
    csv << "metric,value\n";
    csv << "target_registrations," << target_total << "\n";
    csv << "completed_registrations," << total << "\n";
    csv << "completion_percentage," << std::fixed << std::setprecision(2) << (100.0 * total / target_total) << "\n";
    csv << "successful," << successful << "\n";
    csv << "failed," << failed << "\n";
    csv << "success_rate," << (100.0 * successful / total) << "\n";
    csv << "total_time_seconds," << total_time << "\n";
    csv << "throughput_per_second," << (total / total_time) << "\n";
    csv << "min_response_time_ms," << min_time << "\n";
    csv << "max_response_time_ms," << max_time << "\n";
    csv << "mean_response_time_ms," << mean_time << "\n";
    csv << "median_response_time_ms," << median_time << "\n";
    csv << "stdev_response_time_ms," << stdev << "\n";

    // Category statistics
    csv << "\ncategory,type,count,percentage,success_rate,avg_response_time_ms\n";

    // New vs Repeated
    auto new_agents = std::count_if(results.begin(), results.end(),
                                    [](const RegistrationResult& r) { return r.config.is_new; });
    auto new_success = std::count_if(results.begin(), results.end(),
                                     [](const RegistrationResult& r) { return r.config.is_new && r.success; });
    double new_avg_time = 0;
    int new_count = 0;
    for (const auto& r : results) {
        if (r.config.is_new) {
            new_avg_time += r.response_time;
            new_count++;
        }
    }
    if (new_count > 0) new_avg_time /= new_count;

    auto repeated_agents = total - new_agents;
    auto repeated_success = successful - new_success;
    double repeated_avg_time = 0;
    int repeated_count = 0;
    for (const auto& r : results) {
        if (!r.config.is_new) {
            repeated_avg_time += r.response_time;
            repeated_count++;
        }
    }
    if (repeated_count > 0) repeated_avg_time /= repeated_count;

    csv << "agent_type,new," << new_agents << "," << (100.0 * new_agents / total) << ","
        << (new_agents > 0 ? 100.0 * new_success / new_agents : 0) << "," << new_avg_time << "\n";
    csv << "agent_type,repeated," << repeated_agents << "," << (100.0 * repeated_agents / total) << ","
        << (repeated_agents > 0 ? 100.0 * repeated_success / repeated_agents : 0) << "," << repeated_avg_time << "\n";

    // Password correctness
    auto correct_pass = std::count_if(results.begin(), results.end(),
                                      [](const RegistrationResult& r) { return r.config.has_correct_password; });
    auto correct_pass_success = std::count_if(results.begin(), results.end(),
                                              [](const RegistrationResult& r) { return r.config.has_correct_password && r.success; });
    double correct_avg_time = 0;
    int correct_count = 0;
    for (const auto& r : results) {
        if (r.config.has_correct_password) {
            correct_avg_time += r.response_time;
            correct_count++;
        }
    }
    if (correct_count > 0) correct_avg_time /= correct_count;

    auto incorrect_pass = total - correct_pass;
    auto incorrect_pass_success = successful - correct_pass_success;
    double incorrect_avg_time = 0;
    int incorrect_count = 0;
    for (const auto& r : results) {
        if (!r.config.has_correct_password) {
            incorrect_avg_time += r.response_time;
            incorrect_count++;
        }
    }
    if (incorrect_count > 0) incorrect_avg_time /= incorrect_count;

    csv << "password,correct," << correct_pass << "," << (100.0 * correct_pass / total) << ","
        << (correct_pass > 0 ? 100.0 * correct_pass_success / correct_pass : 0) << "," << correct_avg_time << "\n";
    csv << "password,incorrect," << incorrect_pass << "," << (100.0 * incorrect_pass / total) << ","
        << (incorrect_pass > 0 ? 100.0 * incorrect_pass_success / incorrect_pass : 0) << "," << incorrect_avg_time << "\n";

    // Version
    auto modern_version = std::count_if(results.begin(), results.end(),
                                       [](const RegistrationResult& r) { return r.config.is_modern_version; });
    auto modern_success = std::count_if(results.begin(), results.end(),
                                       [](const RegistrationResult& r) { return r.config.is_modern_version && r.success; });
    double modern_avg_time = 0;
    int modern_count = 0;
    for (const auto& r : results) {
        if (r.config.is_modern_version) {
            modern_avg_time += r.response_time;
            modern_count++;
        }
    }
    if (modern_count > 0) modern_avg_time /= modern_count;

    auto normal_version = total - modern_version;
    auto normal_success = successful - modern_success;
    double normal_avg_time = 0;
    int normal_count = 0;
    for (const auto& r : results) {
        if (!r.config.is_modern_version) {
            normal_avg_time += r.response_time;
            normal_count++;
        }
    }
    if (normal_count > 0) normal_avg_time /= normal_count;

    csv << "version,modern," << modern_version << "," << (100.0 * modern_version / total) << ","
        << (modern_version > 0 ? 100.0 * modern_success / modern_version : 0) << "," << modern_avg_time << "\n";
    csv << "version,normal," << normal_version << "," << (100.0 * normal_version / total) << ","
        << (normal_version > 0 ? 100.0 * normal_success / normal_version : 0) << "," << normal_avg_time << "\n";

    // Group
    auto with_group = std::count_if(results.begin(), results.end(),
                                    [](const RegistrationResult& r) { return r.config.has_group; });
    auto group_success = std::count_if(results.begin(), results.end(),
                                      [](const RegistrationResult& r) { return r.config.has_group && r.success; });
    double group_avg_time = 0;
    int group_count = 0;
    for (const auto& r : results) {
        if (r.config.has_group) {
            group_avg_time += r.response_time;
            group_count++;
        }
    }
    if (group_count > 0) group_avg_time /= group_count;

    auto without_group = total - with_group;
    auto no_group_success = successful - group_success;
    double no_group_avg_time = 0;
    int no_group_count = 0;
    for (const auto& r : results) {
        if (!r.config.has_group) {
            no_group_avg_time += r.response_time;
            no_group_count++;
        }
    }
    if (no_group_count > 0) no_group_avg_time /= no_group_count;

    csv << "group,with_group," << with_group << "," << (100.0 * with_group / total) << ","
        << (with_group > 0 ? 100.0 * group_success / with_group : 0) << "," << group_avg_time << "\n";
    csv << "group,without_group," << without_group << "," << (100.0 * without_group / total) << ","
        << (without_group > 0 ? 100.0 * no_group_success / without_group : 0) << "," << no_group_avg_time << "\n";

    csv.close();
    std::cout << "\nStatistics summary written to CSV file: " << csv_file << std::endl;
}

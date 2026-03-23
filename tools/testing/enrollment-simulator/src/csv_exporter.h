#pragma once

#include "types.h"
#include <vector>
#include <string>

class CSVExporter {
public:
    static void write_csv_results(const std::vector<RegistrationResult>& results,
                                  const std::string& csv_file,
                                  double total_time,
                                  int target_total);
};

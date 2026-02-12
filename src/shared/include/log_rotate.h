/* Copyright (C) 2015, Wazuh Inc.
 * All rights reserved.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation
 */

#ifndef LOG_ROTATE_H
#define LOG_ROTATE_H

/**
 * @brief Compress a log file using gzip
 *
 * @param logfile Path to the log file to compress
 */
void OS_CompressLog(const char* logfile);

/**
 * @brief Rotate internal log files (ossec.log / ossec.json)
 *
 * @param compress Whether to compress rotated logs (0 or 1)
 * @param keep_log_days Number of days to keep old logs (0 = forever)
 * @param new_day Whether this is a daily rotation (1) or size-based rotation (0)
 * @param rotate_json Whether to rotate the JSON log file
 * @param daily_rotations Maximum number of daily rotations
 */
void w_rotate_log(int compress, int keep_log_days, int new_day, int rotate_json, int daily_rotations);

#endif /* LOG_ROTATE_H */

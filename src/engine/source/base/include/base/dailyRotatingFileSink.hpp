#ifndef DAILY_ROTATING_FILE_SINK_HPP
#define DAILY_ROTATING_FILE_SINK_HPP

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <limits>
#include <mutex>
#include <optional>
#include <string>
#include <sys/stat.h>
#include <vector>

#include <spdlog/details/file_helper.h>
#include <spdlog/details/null_mutex.h>
#include <spdlog/fmt/fmt.h>
#include <spdlog/sinks/base_sink.h>

// Compression temporarily disabled
// #include <zlibHelper.hpp>

namespace logging
{

/**
 * @file daily_rotating_file_sink.hpp
 *
 * @brief Custom spdlog sink implementing Log4j2-inspired log rotation.
 *
 * This sink combines:
 *
 *   - time-based rotation
 *   - size-based rotation
 *   - retention by file count
 *   - retention by accumulated size
 *   - gzip compression for rotated files (TEMPORARILY DISABLED)
 *
 * Rotation occurs when:
 *
 *   1) The configured rotation time is reached
 *   OR
 *   2) The active log file exceeds max_size
 *
 * Rotated files follow this naming pattern:
 *
 *     basename-YYYY-MM-DD-N.ext  (compression temporarily disabled, .gz removed)
 *
 * Example:
 *
 *     wazuh-engine.log                (active file)
 *     wazuh-engine-2026-03-09-1.log  (first rotation that day)
 *     wazuh-engine-2026-03-09-2.log  (second rotation same day)
 *     wazuh-engine-2026-03-10-1.log  (next day rotation)
 *
 * Design notes for reviewers:
 *
 *   - The active log file always keeps the original base filename.
 *   - Rotation uses OR semantics, matching Log4j2 behavior:
 *
 *         rotate_by_time || rotate_by_size
 *
 *   - Cleanup is executed only during rotation, not on every log write.
 *     This avoids expensive directory scans in the hot path.
 *
 *   - Compression is TEMPORARILY DISABLED.
 *     Previously: Compression was synchronous and happened while the sink mutex
 *     was held. This kept the implementation simple and safe, but could
 *     temporarily block logging during large rotations.
 *
 *   - Previously: If compression failed, the rotated file was preserved uncompressed
 *     to avoid losing logs. Cleanup accounted for both compressed and
 *     uncompressed rotated files.
 *
 * Thread-safety:
 *
 *   This sink derives from spdlog::sinks::base_sink<std::mutex>.
 *   All sink operations are serialized by the base sink mutex.
 */
class daily_rotating_file_sink final : public spdlog::sinks::base_sink<std::mutex>
{
public:
    /**
     * @brief Configuration structure for daily rotating file sink.
     *
     * This sink implements Log4j2-inspired rotation policies:───────────────────────────────────────────────────────────────────────┘
     *
     * Field mapping:
     *   - filePath               → fileName (active log file path)
     *   - maxFileSize            → SizeBasedTriggeringPolicy/size
     *   - rotationHour/Minute    → TimeBasedTriggeringPolicy (modulate=true)
     *   - maxFiles               → DefaultRolloverStrategy/max
     *   - maxAccumulatedSize     → IfAccumulatedFileSize/exceeds
     *   - rotationIntervalSeconds → Custom extension for testing (not in Log4j2)
     */
    struct Config
    {
        /// Base filename for the active log file
        /// Example: "/var/log/wazuh-engine.log"
        /// Log4j2: <RollingFile fileName="...">
        spdlog::filename_t filePath;

        /// Maximum active file size in bytes before rotation (default: 128 MB)
        /// Log4j2: <SizeBasedTriggeringPolicy size="128 MB"/>
        std::size_t maxFileSize = 128 * 1024 * 1024;

        /// Hour of day for time-based rotation [0..23] (only used if rotationIntervalSeconds == 0)
        /// Log4j2: <TimeBasedTriggeringPolicy modulate="true"/> (rotates at midnight by default)
        int rotationHour = 0;

        /// Minute of hour for time-based rotation [0..59] (only used if rotationIntervalSeconds == 0)
        /// Log4j2: Part of TimeBasedTriggeringPolicy configuration
        int rotationMinute = 0;

        /// Maximum number of rotated files to keep (0 = unlimited)
        /// Log4j2: <DefaultRolloverStrategy max="...">
        std::size_t maxFiles = 0;

        /// Maximum total size of rotated files in bytes (0 = unlimited)
        /// Log4j2: <IfAccumulatedFileSize exceeds="...">
        std::size_t maxAccumulatedSize = 0;

        /// If true, truncate the file on initial open (does NOT affect files after rotation)
        /// Log4j2: <RollingFile append="false">
        bool truncate = false;

        /// Rotation interval in seconds (0 = use rotationHour/rotationMinute, >0 = interval mode)
        /// Custom extension for testing - not available in Log4j2
        /// When > 0, ignores rotationHour/rotationMinute and rotates every N seconds
        int rotationIntervalSeconds = 0;
    };

    /**
     * @brief Construct a new daily rotating file sink with configuration struct.
     *
     * @param config Configuration structure with rotation settings.
     *
     * @throws spdlog::spdlog_ex if rotation time is invalid or parent directory doesn't exist.
     */
    explicit daily_rotating_file_sink(const Config& config)
        : base_filename_(config.filePath)
        , max_size_(config.maxFileSize)
        , rotation_h_(config.rotationHour)
        , rotation_m_(config.rotationMinute)
        , max_files_(config.maxFiles)
        , truncate_(config.truncate)
        , max_accumulated_size_(config.maxAccumulatedSize)
        , rotation_interval_seconds_(config.rotationIntervalSeconds)
        , current_size_(0)
        , file_index_(1)
    {
        validate_and_init_();
    }

    /**
     * @brief Returns the current active filename.
     *
     * This is mostly useful for tests/debugging.
     */
    spdlog::filename_t filename()
    {
        std::lock_guard<std::mutex> lock(this->mutex_);
        return file_helper_.filename();
    }

protected:
    /**
     * @brief Main logging entrypoint called by spdlog.
     *
     * Execution flow:
     *
     *   1) Format the message
     *   2) Evaluate rotation conditions
     *   3) Rotate if needed
     *   4) Write the message
     *
     * Rotation uses OR semantics:
     *
     *   - rotate when scheduled time is reached
     *   - OR when current file would exceed max_size
     *
     * If both conditions are true simultaneously, only one rotation occurs.
     *
     * Note:
     *
     *   Rotation is performed BEFORE writing the triggering message.
     *   This ensures the triggering message goes to the new active file.
     */
    void sink_it_(const spdlog::details::log_msg& msg) override
    {
        spdlog::memory_buf_t formatted;
        this->formatter_->format(msg, formatted);

        const auto msg_time = msg.time;
        const bool rotate_by_time = msg_time >= rotation_tp_;
        const bool rotate_by_size = (current_size_ + formatted.size()) > max_size_;

        if (rotate_by_time || rotate_by_size)
        {
            rotate_(msg_time, rotate_by_time);
        }

        file_helper_.write(formatted);
        current_size_ += formatted.size();
    }

    /**
     * @brief Flush active file contents.
     */
    void flush_() override { file_helper_.flush(); }

private:
    /**
     * @brief Parsed representation of the rotated filename middle section.
     *
     * Expected source string:
     *
     *     YYYY-MM-DD-N
     *
     * Example:
     *
     *     2026-03-09-3
     *
     * We parse this into:
     *
     *   - date  = "2026-03-09"
     *   - index = 3
     *
     * This parsed representation is used to sort files deterministically
     * during cleanup.
     */
    struct ParsedRotationName
    {
        std::string date;
        std::size_t index;
    };

    /**
     * @brief Metadata used during retention cleanup.
     *
     * Sorting order:
     *
     *   1) parsed date
     *   2) parsed numeric index
     *   3) filename as final tiebreaker
     *
     * Important:
     *
     *   We do NOT sort lexicographically by raw filename alone because
     *   that would produce incorrect ordering for indices like:
     *
     *       ...-10.log  <  ...-2.log
     *
     *   when compared as plain strings.
     */
    struct FileInfo
    {
        std::string path;
        std::string filename;
        std::string date;
        std::size_t index;
        std::time_t mtime;
        std::int64_t size;
        bool valid;

        bool operator<(const FileInfo& other) const
        {
            if (date != other.date)
            {
                return date < other.date;
            }
            if (index != other.index)
            {
                return index < other.index;
            }
            return filename < other.filename;
        }
    };

    /**
     * @brief Convert a log clock time point to YYYY-MM-DD local date.
     *
     * Note:
     *
     *   The sink stores and compares dates as strings because lexicographic
     *   ordering is correct for the YYYY-MM-DD format.
     */
    std::string get_date(const spdlog::log_clock::time_point& tp) const
    {
        std::time_t time =
            std::chrono::system_clock::to_time_t(std::chrono::time_point_cast<std::chrono::system_clock::duration>(
                tp - spdlog::log_clock::now() + std::chrono::system_clock::now()));

        std::tm tm_time {};
        localtime_r(&time, &tm_time);

        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%d", &tm_time);
        return std::string(buf);
    }

    /**
     * @brief Convenience wrapper for current local date.
     */
    std::string get_current_date() const { return get_date(spdlog::log_clock::now()); }

    /**
     * @brief Build the rotated filename.
     *
     * Pattern (compression temporarily disabled):
     *
     *     basename-YYYY-MM-DD-N.ext
     *
     * Example:
     *
     *     wazuh-engine-2026-03-09-1.log
     */
    spdlog::filename_t calc_rotated_filename(const std::string& date, std::size_t index) const
    {
        auto [basename, ext] = split_filename(base_filename_);
        // Compression temporarily disabled - removed .gz extension
        return fmt::format("{}-{}-{}{}", basename, date, index, ext);
    }

    /**
     * @brief Split filename into basename and extension.
     *
     * Examples:
     *
     *   "/var/log/app.log" -> {"/var/log/app", ".log"}
     *   "/var/log/app"     -> {"/var/log/app", ""}
     *
     * Note:
     *
     *   The split is based on the last '.' occurring after the last path
     *   separator, so dots in directory names do not count as extensions.
     */
    std::pair<std::string, std::string> split_filename(const spdlog::filename_t& filename) const
    {
        const auto last_dot = filename.find_last_of('.');
        const auto last_slash = filename.find_last_of("/\\");

        if (last_dot == std::string::npos || (last_slash != std::string::npos && last_dot < last_slash))
        {
            return {filename, ""};
        }

        return {filename.substr(0, last_dot), filename.substr(last_dot)};
    }

    /**
     * @brief Compute the next scheduled rotation time.
     *
     * Two modes:
     *
     * 1) Interval mode (rotation_interval_seconds_ > 0):
     *    Rotates every N seconds from now. Useful for testing.
     *
     * 2) Modulate mode (rotation_interval_seconds_ == 0):
     *    The scheduled rotation time is defined by rotation_h_ and rotation_m_.
     *    Example: rotation_h_ = 0, rotation_m_ = 0 means daily rotation at local midnight.
     *    If today's target time already passed, the next rotation is scheduled for tomorrow.
     *
     * Note:
     *
     *   The calculation is done in system_clock and then translated to
     *   spdlog::log_clock using a duration. This keeps the logic simple
     *   without assuming direct clock interchangeability.
     */
    spdlog::log_clock::time_point next_rotation_tp_()
    {
        // Interval mode: rotate every N seconds
        if (rotation_interval_seconds_ > 0)
        {
            return spdlog::log_clock::now() + std::chrono::seconds(rotation_interval_seconds_);
        }

        // Modulate mode: rotate at specific hour:minute of day
        const auto now_sys = std::chrono::system_clock::now();
        const std::time_t now_time = std::chrono::system_clock::to_time_t(now_sys);

        std::tm tm_time {};
        localtime_r(&now_time, &tm_time);

        tm_time.tm_hour = rotation_h_;
        tm_time.tm_min = rotation_m_;
        tm_time.tm_sec = 0;

        auto rotation_time = std::mktime(&tm_time);
        auto rotation_tp_sys = std::chrono::system_clock::from_time_t(rotation_time);

        if (rotation_tp_sys <= now_sys)
        {
            rotation_tp_sys += std::chrono::hours(24);
        }

        const auto duration_until_rotation = rotation_tp_sys - now_sys;
        return spdlog::log_clock::now() + duration_until_rotation;
    }

    /**
     * @brief Perform a rollover of the active log file.
     *
     * Rotation flow:
     *
     *   1) Close active file
     *   2) Determine rotation date
     *   3) Reset file index if the date changed
     *   4) Find next available rotated filename
     *   5) Rename active file to rotated filename (compression disabled)
     *   6) Reopen fresh active file
     *   7) Run retention cleanup
     *
     * Failure handling:
     *
     *   - If rename fails:
     *       rotation is aborted and a fresh active file is opened
     *
     * Note:
     *
     *   Compression is TEMPORARILY DISABLED.
     *   Previously: Compression was synchronous and happened under the sink mutex.
     *   This was the main simplicity/performance trade-off in the design.
     */
    void rotate_(const spdlog::log_clock::time_point& msg_time, bool date_changed)
    {
        using spdlog::details::os::path_exists;
        using spdlog::details::os::rename;

        file_helper_.close();

        const auto rotation_date = get_date(msg_time);

        if (date_changed || rotation_date != current_date_)
        {
            current_date_ = rotation_date;
            file_index_ = 1;
            rotation_tp_ = next_rotation_tp_();
        }

        spdlog::filename_t target_filename;
        do
        {
            target_filename = calc_rotated_filename(current_date_, file_index_);
            ++file_index_;
        } while (path_exists(target_filename));

        if (path_exists(base_filename_))
        {
            // Compression disabled temporarily - just rename without .gz extension
            if (rename(base_filename_, target_filename) != 0)
            {
                // Best-effort recovery:
                // reopen the active filename and continue logging.
                file_helper_.open(base_filename_, false);
                current_size_ = 0;
                return;
            }

            /* Compression disabled temporarily
            auto temp_filename = target_filename.substr(0, target_filename.size() - 3); // remove ".gz"

            if (rename(base_filename_, temp_filename) != 0)
            {
                // Best-effort recovery:
                // reopen the active filename and continue logging.
                file_helper_.open(base_filename_, false);
                current_size_ = 0;
                return;
            }

            bool compression_successful = false;
            try
            {
                Utils::ZlibHelper::gzipCompress(temp_filename, target_filename, 6);
                compression_successful = true;
            }
            catch (const std::exception&)
            {
                // Keep the uncompressed rotated file.
                // Better to preserve logs than lose them.
            }

            if (compression_successful)
            {
                std::error_code ec;
                std::filesystem::remove(temp_filename, ec);
            }
            */
        }

        // Never truncate after rollover; we want a fresh active file.
        file_helper_.open(base_filename_, false);
        current_size_ = 0;

        // NOTE:
        //
        // Cleanup is intentionally triggered only during rotations,
        // not on every log write. This avoids expensive filesystem
        // scans in the hot logging path.
        //
        // Trade-off:
        // cleanup only happens if rotation occurs.
        if (max_files_ > 0 || max_accumulated_size_ > 0)
        {
            delete_old_files_();
        }
    }

    /**
     * @brief Validate basic date ranges.
     *
     * This is intentionally lightweight validation:
     *
     *   - month: 1..12
     *   - day:   1..31
     *
     * Note:
     *
     *   We do not perform full calendar validation here
     *   (e.g. leap year / exact month length) because cleanup only needs
     *   stable filename ordering and basic filtering of malformed names.
     */
    bool is_valid_date_components(int month, int day) const
    {
        return month >= 1 && month <= 12 && day >= 1 && day <= 31;
    }

    /**
     * @brief Parse the middle section of a rotated filename.
     *
     * Expected format:
     *
     *     YYYY-MM-DD-N
     *
     * Example:
     *
     *     2026-03-09-3
     *
     * Parsing rules:
     *
     *   - validate structural format
     *   - validate month/day ranges
     *   - validate that the index is numeric
     *   - protect conversion against overflow/exception
     *
     * Files not matching this format are ignored by cleanup.
     */
    std::optional<ParsedRotationName> parse_rotated_middle(const std::string& middle) const
    {
        if (middle.size() < 12)
        {
            return std::nullopt;
        }

        const bool valid_format = std::isdigit(static_cast<unsigned char>(middle[0]))
                                  && std::isdigit(static_cast<unsigned char>(middle[1]))
                                  && std::isdigit(static_cast<unsigned char>(middle[2]))
                                  && std::isdigit(static_cast<unsigned char>(middle[3])) && middle[4] == '-'
                                  && std::isdigit(static_cast<unsigned char>(middle[5]))
                                  && std::isdigit(static_cast<unsigned char>(middle[6])) && middle[7] == '-'
                                  && std::isdigit(static_cast<unsigned char>(middle[8]))
                                  && std::isdigit(static_cast<unsigned char>(middle[9])) && middle[10] == '-';

        if (!valid_format)
        {
            return std::nullopt;
        }

        const std::string date_part = middle.substr(0, 10);
        const std::string month_part = middle.substr(5, 2);
        const std::string day_part = middle.substr(8, 2);
        const std::string index_part = middle.substr(11);

        if (index_part.empty())
        {
            return std::nullopt;
        }

        const bool index_valid =
            std::all_of(index_part.begin(), index_part.end(), [](unsigned char c) { return std::isdigit(c); });

        if (!index_valid)
        {
            return std::nullopt;
        }

        const int month = std::stoi(month_part);
        const int day = std::stoi(day_part);

        if (!is_valid_date_components(month, day))
        {
            return std::nullopt;
        }

        try
        {
            const auto parsed = std::stoull(index_part);
            if (parsed > static_cast<unsigned long long>(std::numeric_limits<std::size_t>::max()))
            {
                return std::nullopt;
            }

            return ParsedRotationName {date_part, static_cast<std::size_t>(parsed)};
        }
        catch (const std::exception&)
        {
            return std::nullopt;
        }
    }

    /**
     * @brief Delete old rotated files according to retention rules.
     *
     * This method scans the log directory for rotated files matching:
     *
     *   basename-YYYY-MM-DD-N.ext
     *
     * Note: Compression is temporarily disabled.
     *
     * Cleanup algorithm:
     *
     *   1) Scan directory
     *   2) Match rotated file pattern
     *   3) Parse date + index
     *   4) Sort deterministically by parsed date and numeric index
     *   5) Apply accumulated-size retention
     *   6) Apply file-count retention
     *
     * Deletion semantics:
     *
     *   A file is marked invalid only if the delete call succeeds.
     *   If deletion fails, the file remains part of the accounting.
     *
     * Note:
     *
     *   This avoids inconsistencies where the in-memory retention state
     *   would assume a file is gone while it still exists on disk.
     */
    void delete_old_files_()
    {
        using spdlog::details::os::remove_if_exists;

        std::vector<FileInfo> rotated_files;
        std::int64_t total_size = 0;

        auto dir_path = std::filesystem::path(base_filename_).parent_path();
        if (dir_path.empty())
        {
            dir_path = ".";
        }

        const auto base_name = std::filesystem::path(base_filename_).filename().string();
        const auto [basename, ext] = split_filename(base_name);

        // Match pattern: basename-YYYY-MM-DD-N.ext
        // Note: Compression temporarily disabled, no .gz files expected
        const std::string pattern_prefix = basename + "-";
        const std::string pattern_suffix = ext;

        try
        {
            for (const auto& entry : std::filesystem::directory_iterator(dir_path))
            {
                if (!entry.is_regular_file())
                {
                    continue;
                }

                const auto filename = entry.path().filename().string();

                // Check if filename matches pattern: basename-YYYY-MM-DD-N.ext
                const bool matches =
                    filename.find(pattern_prefix) == 0 && filename.size() >= pattern_suffix.size()
                    && filename.compare(filename.size() - pattern_suffix.size(), pattern_suffix.size(), pattern_suffix)
                           == 0;

                if (!matches)
                {
                    continue;
                }

                const auto middle_start = pattern_prefix.size();
                const auto middle_end = filename.size() - pattern_suffix.size();
                const auto middle = filename.substr(middle_start, middle_end - middle_start);
                const auto parsed = parse_rotated_middle(middle);
                if (!parsed.has_value())
                {
                    continue;
                }

                const auto filepath = entry.path().string();
                const auto size = get_file_size(filepath);
                const auto mtime = get_file_mtime(filepath);

                if (size >= 0)
                {
                    rotated_files.push_back({filepath, filename, parsed->date, parsed->index, mtime, size, true});
                    total_size += size;
                }
            }
        }
        catch (const std::filesystem::filesystem_error&)
        {
            return;
        }

        if (rotated_files.empty())
        {
            return;
        }

        // Sort by parsed date + numeric index.
        std::sort(rotated_files.begin(), rotated_files.end());

        std::size_t files_deleted = 0;

        // Strategy 1:
        // Delete oldest files until accumulated rotated size fits the limit.
        if (max_accumulated_size_ > 0 && total_size > static_cast<std::int64_t>(max_accumulated_size_))
        {
            const auto size_to_free = total_size - static_cast<std::int64_t>(max_accumulated_size_);
            std::int64_t freed_size = 0;

            for (auto& file : rotated_files)
            {
                if (freed_size >= size_to_free)
                {
                    break;
                }

                if (!file.valid)
                {
                    continue;
                }

                const int rc = remove_if_exists(file.path);
                const bool removed = (rc == 0); // Assumes spdlog wrapper returns 0 on success.

                if (removed)
                {
                    freed_size += file.size;
                    total_size -= file.size;
                    file.valid = false;
                    ++files_deleted;
                }
            }
        }

        // Strategy 2:
        // Delete oldest remaining files until file-count limit fits.
        if (max_files_ > 0)
        {
            const std::size_t remaining_files = rotated_files.size() - files_deleted;
            if (remaining_files > max_files_)
            {
                const std::size_t files_to_delete = remaining_files - max_files_;
                std::size_t deleted_count = 0;

                for (auto& file : rotated_files)
                {
                    if (deleted_count >= files_to_delete)
                    {
                        break;
                    }

                    if (!file.valid)
                    {
                        continue;
                    }

                    const int rc = remove_if_exists(file.path);
                    const bool removed = (rc == 0); // Assumes spdlog wrapper returns 0 on success.

                    if (removed)
                    {
                        file.valid = false;
                        ++deleted_count;
                    }
                }
            }
        }
    }

    /**
     * @brief Get file modification time.
     *
     * Returns 0 if stat fails.
     *
     * note:
     *
     *   mtime is not used as the primary cleanup ordering key.
     *   It is retained only as auxiliary metadata/debug value.
     */
    std::time_t get_file_mtime(const std::string& filepath) const
    {
        struct stat file_stat
        {
        };
        if (stat(filepath.c_str(), &file_stat) == 0)
        {
            return file_stat.st_mtime;
        }
        return 0;
    }

    /**
     * @brief Get file size in bytes.
     *
     * Returns:
     *
     *   - file size if stat succeeds
     *   - -1 if stat fails
     *
     * Returning -1 lets the caller distinguish:
     *
     *   - empty file (size 0)
     *   - stat error
     */
    std::int64_t get_file_size(const std::string& filepath) const
    {
        struct stat file_stat
        {
        };
        if (stat(filepath.c_str(), &file_stat) == 0)
        {
            return static_cast<std::int64_t>(file_stat.st_size);
        }
        return -1;
    }

    /**
     * @brief Validate configuration and initialize sink.
     *
     * Common initialization logic shared by all constructors.
     */
    void validate_and_init_()
    {
        // Validate rotation interval
        if (rotation_interval_seconds_ < 0)
        {
            throw spdlog::spdlog_ex("daily_rotating_file_sink: Invalid rotation interval (must be >= 0)");
        }

        // Validate rotation time (only when using modulate mode)
        if (rotation_interval_seconds_ == 0
            && (rotation_h_ < 0 || rotation_h_ > 23 || rotation_m_ < 0 || rotation_m_ > 59))
        {
            throw spdlog::spdlog_ex("daily_rotating_file_sink: Invalid rotation time");
        }

        // Validate that parent directory exists before attempting to open file
        auto parent_path = std::filesystem::path(base_filename_).parent_path();
        if (!parent_path.empty() && !std::filesystem::exists(parent_path))
        {
            throw spdlog::spdlog_ex("daily_rotating_file_sink: Parent directory does not exist: "
                                    + parent_path.string());
        }

        // Initial open of the active file.
        // truncate_ only affects this first open.
        file_helper_.open(base_filename_, truncate_);
        current_size_ = file_helper_.size();
        current_date_ = get_current_date();
        rotation_tp_ = next_rotation_tp_();
    }

    // Active log file path.
    spdlog::filename_t base_filename_;

    // Max size of the active file before rollover.
    std::size_t max_size_;

    // Scheduled daily rotation time.
    int rotation_h_;
    int rotation_m_;

    // Retention by file count for rotated files.
    std::size_t max_files_;

    // Only affects the very first file open in the constructor.
    bool truncate_;

    // Retention by accumulated size of rotated files.
    std::size_t max_accumulated_size_;

    // Rotation interval in seconds (0 = use hour/minute modulate mode).
    int rotation_interval_seconds_;

    // Approximate current active file size.
    // Updated after each write and reset after rotation.
    std::size_t current_size_;

    // Next candidate index for the current date.
    std::size_t file_index_;

    // Current active date bucket (YYYY-MM-DD).
    std::string current_date_;

    // Next scheduled time-based rotation timestamp.
    spdlog::log_clock::time_point rotation_tp_;

    // spdlog helper used to manage the active file.
    spdlog::details::file_helper file_helper_;
};

} // namespace logging

#endif // DAILY_ROTATING_FILE_SINK_HPP

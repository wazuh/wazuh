#include "simulator.h"
#include "agent_config.h"
#include "types.h"

#include <iostream>
#include <fstream>
#include <vector>
#include <csignal>

// Custom streambuf that writes to multiple streams
class MultiStreamBuf : public std::streambuf {
private:
    std::vector<std::streambuf*> buffers;

public:
    void add_buffer(std::streambuf* buf) {
        if (buf) buffers.push_back(buf);
    }

protected:
    virtual int overflow(int c) override {
        if (c == EOF) {
            return !EOF;
        } else {
            bool all_ok = true;
            for (auto* buf : buffers) {
                if (buf->sputc(c) == EOF) {
                    all_ok = false;
                }
            }
            return all_ok ? c : EOF;
        }
    }

    virtual int sync() override {
        bool all_ok = true;
        for (auto* buf : buffers) {
            if (buf->pubsync() != 0) {
                all_ok = false;
            }
        }
        return all_ok ? 0 : -1;
    }
};

// Signal handler
void signal_handler(int signum) {
    if (signum == SIGINT) {
        std::cout << "\n\n[!] Ctrl+C detected. Stopping simulation gracefully..." << std::endl;
        stop_simulation = true;
    }
}

void print_help(const char* program_name) {
    std::cout << "Usage: " << program_name << " [options]" << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  --host HOST                 Target host (default: localhost)" << std::endl;
    std::cout << "  --port PORT                 Target port (default: 1515)" << std::endl;
    std::cout << "  --password PASS             Correct password (default: topsecret)" << std::endl;
    std::cout << "  --log-file FILE             Write output to file (and stdout)" << std::endl;
    std::cout << "  --csv-file FILE             Export results to CSV file" << std::endl;
    std::cout << "  --threads N                 Number of threads (default: 4)" << std::endl;
    std::cout << "  --total N                   Total registrations (default: 10000)" << std::endl;
    std::cout << "  --new-ratio RATIO           Ratio of new agents (default: 0.5)" << std::endl;
    std::cout << "  --incorrect-pass-ratio R    Ratio of incorrect passwords (default: 0.01)" << std::endl;
    std::cout << "  --modern-version-ratio R    Ratio of modern version (default: 0.05)" << std::endl;
    std::cout << "  --group-ratio RATIO         Ratio with group (default: 0.5)" << std::endl;
    std::cout << "  --connect-delay MS          Delay before TLS handshake (default: 0)" << std::endl;
    std::cout << "                              Can be a range: MIN-MAX (e.g., 100-500)" << std::endl;
    std::cout << "  --send-delay MS             Delay before sending request (default: 0)" << std::endl;
    std::cout << "                              Can be a range: MIN-MAX (e.g., 50-200)" << std::endl;
}

int main(int argc, char* argv[]) {
    // Set up signal handler
    signal(SIGINT, signal_handler);
    signal(SIGPIPE, SIG_IGN);  // Ignore SIGPIPE to handle broken connections gracefully

    // Default parameters
    std::string host = "localhost";
    int port = 1515;
    std::string password = "topsecret";
    std::string log_file = "";
    std::string csv_file = "";
    int threads = 4;
    int total = 10000;
    double new_ratio = 0.5;
    double incorrect_pass_ratio = 0.01;
    double modern_version_ratio = 0.05;
    double group_ratio = 0.5;
    DelayRange connect_delay(0);
    DelayRange send_delay(0);

    // Parse command line arguments
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--host" && i + 1 < argc) {
            host = argv[++i];
        } else if (arg == "--port" && i + 1 < argc) {
            port = std::stoi(argv[++i]);
        } else if (arg == "--password" && i + 1 < argc) {
            password = argv[++i];
        } else if (arg == "--log-file" && i + 1 < argc) {
            log_file = argv[++i];
        } else if (arg == "--csv-file" && i + 1 < argc) {
            csv_file = argv[++i];
        } else if (arg == "--threads" && i + 1 < argc) {
            threads = std::stoi(argv[++i]);
        } else if (arg == "--total" && i + 1 < argc) {
            total = std::stoi(argv[++i]);
        } else if (arg == "--new-ratio" && i + 1 < argc) {
            new_ratio = std::stod(argv[++i]);
        } else if (arg == "--incorrect-pass-ratio" && i + 1 < argc) {
            incorrect_pass_ratio = std::stod(argv[++i]);
        } else if (arg == "--modern-version-ratio" && i + 1 < argc) {
            modern_version_ratio = std::stod(argv[++i]);
        } else if (arg == "--group-ratio" && i + 1 < argc) {
            group_ratio = std::stod(argv[++i]);
        } else if (arg == "--connect-delay" && i + 1 < argc) {
            connect_delay = DelayRange::parse(argv[++i]);
        } else if (arg == "--send-delay" && i + 1 < argc) {
            send_delay = DelayRange::parse(argv[++i]);
        } else if (arg == "--help") {
            print_help(argv[0]);
            return 0;
        }
    }

    // Set up logging if requested
    std::ofstream log_stream;
    MultiStreamBuf multi_buf;
    std::streambuf* original_cout = std::cout.rdbuf();

    if (!log_file.empty()) {
        log_stream.open(log_file);
        if (log_stream.is_open()) {
            multi_buf.add_buffer(original_cout);
            multi_buf.add_buffer(log_stream.rdbuf());
            std::cout.rdbuf(&multi_buf);
            std::cout << "Logging to: " << log_file << std::endl;
        } else {
            std::cerr << "Warning: Could not open log file: " << log_file << std::endl;
        }
    }

    WazuhAuthSimulator simulator(host, port, password);
    simulator.run_simulation(threads, total, new_ratio, incorrect_pass_ratio,
                            modern_version_ratio, group_ratio, connect_delay, send_delay, csv_file);

    // Restore original cout
    if (log_stream.is_open()) {
        std::cout.rdbuf(original_cout);
        log_stream.close();
    }

    return 0;
}

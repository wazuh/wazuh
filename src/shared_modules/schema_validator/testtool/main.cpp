/*
 * Wazuh Schema Validator Test tool
 *
 * Smoke test used by the RTR / ASAN checks. It exercises the process-wide
 * SchemaValidatorFactory singleton the same way the agent modules do
 * (concurrent check-then-act initialization from several threads) and then
 * validates a sample message against an embedded schema.
 */

#include <atomic>
#include <iostream>
#include <string>
#include <thread>
#include <vector>

#include "schemaValidator.hpp"

using namespace SchemaValidator;

int main()
{
    try
    {
        auto& factory = SchemaValidatorFactory::getInstance();

        // Initialize the factory concurrently, mirroring the syscollector / sca /
        // vulnerability_scanner startup in wazuh-modulesd (each runs the same
        // check-then-act guard against the shared singleton).
        constexpr int kThreads = 8;
        std::atomic<bool> go {false};
        std::vector<std::thread> threads;
        threads.reserve(kThreads);

        for (int t = 0; t < kThreads; ++t)
        {
            threads.emplace_back([&]()
            {
                while (!go.load())
                {
                    // Align the start so all threads hit initialize() together.
                    std::this_thread::yield();
                }

                if (!factory.isInitialized())
                {
                    factory.initialize();
                }
            });
        }

        go.store(true);

        for (auto& thread : threads)
        {
            thread.join();
        }

        if (!factory.isInitialized())
        {
            std::cout << "[Test schema_validator] No embedded schemas; nothing to validate." << std::endl;
            return 0;
        }

        // Validate a sample message against the first available index. An empty
        // object is valid for these strict-mode templates (all fields optional,
        // no extra fields present).
        const std::vector<std::string> candidates =
        {
            "wazuh-states-inventory-hardware",
            "wazuh-states-inventory-system",
            "wazuh-states-fim-files",
            "wazuh-states-sca",
        };

        for (const auto& index : candidates)
        {
            auto validator = factory.getValidator(index);

            if (validator)
            {
                auto result = validator->validate(std::string("{}"));
                std::cout << "[Test schema_validator] validated against '" << index << "': "
                          << (result.isValid ? "OK" : "FAIL") << std::endl;

                if (!result.isValid)
                {
                    for (const auto& error : result.errors)
                    {
                        std::cerr << "  " << error << std::endl;
                    }

                    return 1;
                }

                std::cout << "OK" << std::endl;
                return 0;
            }
        }

        std::cout << "[Test schema_validator] No candidate index embedded; OK." << std::endl;
        return 0;
    }
    catch (const std::exception& e)
    {
        std::cerr << "[Test schema_validator] Unhandled exception: " << e.what() << std::endl;
        return 1;
    }
    catch (...)
    {
        std::cerr << "[Test schema_validator] Unknown unhandled exception" << std::endl;
        return 1;
    }
}

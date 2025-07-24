#pragma once

#include "sca.h"
#include <sca_impl.hpp>

#include <sca_impl.hpp>

#include <functional>
#include <memory>
#include <string>

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

class EXPORTED SCA final
{
public:
    static SCA& instance()
    {
        static SCA s_instance;
        return s_instance;
    }

    void init(const std::function<void(const modules_log_level_t, const std::string&)> logFunction);
    void setup(const struct wm_sca_t* sca_config);
    void run();
    void destroy();
    void push(const std::string& data);

private:
    SCA();
    ~SCA() = default;
    SCA(const SCA&) = delete;
    SCA& operator=(const SCA&) = delete;

    std::unique_ptr<SecurityConfigurationAssessment> m_sca;

    // workaround for integration tests
    // it should be possible to call setup multiple times
    // but there's segfault when commiting a db transaction
    // on a second setup call
    // this is a temporary solution until the issue is resolved
    bool m_setupCalled = false;
};

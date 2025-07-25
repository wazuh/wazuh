#include <sca_impl.hpp>

#include <sca_event_handler.hpp>
#include <sca_policy.hpp>
#include <sca_policy_loader.hpp>

#include <dbsync.hpp>
#include <filesystem_wrapper.hpp>
// #include <logger.hpp>

#include <thread>
#include <iostream>

// Static member definition
int (*SecurityConfigurationAssessment::s_wmExecFunc)(char*, char**, int*, int, const char*) = nullptr;

constexpr auto POLICY_SQL_STATEMENT {
    R"(CREATE TABLE IF NOT EXISTS sca_policy (
    id TEXT PRIMARY KEY,
    name TEXT,
    file TEXT,
    description TEXT,
    refs TEXT);)"};

constexpr auto CHECK_SQL_STATEMENT {
    R"(CREATE TABLE IF NOT EXISTS sca_check (
    id TEXT PRIMARY KEY,
    policy_id TEXT REFERENCES sca_policy(id),
    name TEXT,
    description TEXT,
    rationale TEXT,
    remediation TEXT,
    refs TEXT,
    result TEXT DEFAULT 'Not run',
    reason TEXT,
    condition TEXT,
    compliance TEXT,
    rules TEXT);)"};

SecurityConfigurationAssessment::SecurityConfigurationAssessment(
    std::string dbPath,
    std::string agentUUID,
    std::shared_ptr<IDBSync> dbSync,
    std::shared_ptr<IFileSystemWrapper> fileSystemWrapper)
    : m_agentUUID(std::move(agentUUID))
    , m_dBSync(dbSync ? std::move(dbSync)
                      : std::make_shared<DBSync>(
                            HostType::AGENT,
                            DbEngineType::SQLITE3,
                            dbPath,
                            GetCreateStatement(),
                            DbManagement::PERSISTENT))
    , m_fileSystemWrapper(fileSystemWrapper ? std::move(fileSystemWrapper)
                                            : std::make_shared<file_system::FileSystemWrapper>())
{
    std::cout << "SecurityConfigurationAssessment initialized with agent UUID: " << m_agentUUID << std::endl;
}

void SecurityConfigurationAssessment::Run()
{
    if (!m_enabled)
    {
        // LogInfo("SCA module is disabled.");
        return;
    }

    m_keepRunning = true;

    // LogInfo("SCA module running.");

    while(m_keepRunning)
    {
        if (m_scanOnStart)
        {
            // LogInfo("SCA module scan on start.");
            for (auto& policy : m_policies)
            {
                if (!m_keepRunning)
                {
                    return;
                }

                policy->Run(
                    m_scanInterval,
                    m_scanOnStart,
                    [this](const std::string& policyId, const std::string& checkId, const std::string& result)
                    {
                        const SCAEventHandler eventHandler(m_agentUUID, m_dBSync, m_pushMessage);
                        eventHandler.ReportCheckResult(policyId, checkId, result);
                    },
                    nullptr
                );
            }
        }

        std::this_thread::sleep_for(std::chrono::milliseconds(m_scanInterval));
    }
}

void SecurityConfigurationAssessment::Setup(bool enabled,
                                            bool scanOnStart,
                                            std::time_t scanInterval,
                                            const std::vector<std::string>& policies,
                                            const std::vector<std::string>& disabledPolicies)
{
    m_enabled = enabled;
    m_scanOnStart = scanOnStart;
    m_scanInterval = scanInterval;
    m_policies = [this, &policies, &disabledPolicies]()
    {
        const SCAPolicyLoader policyLoader(policies, disabledPolicies, m_fileSystemWrapper, m_dBSync);
        return policyLoader.LoadPolicies(
            [this](auto policyData, auto checksData)
            {
                const SCAEventHandler eventHandler(m_agentUUID, m_dBSync, m_pushMessage);
                eventHandler.ReportPoliciesDelta(policyData, checksData);
            });
    }();
}

void SecurityConfigurationAssessment::Stop()
{
    m_keepRunning = false;

    for (auto& policy : m_policies)
    {
        policy->Stop();
    }
    // LogInfo("SCA module stopped.");
}

const std::string& SecurityConfigurationAssessment::Name() const
{
    return m_name;
}

void SecurityConfigurationAssessment::SetPushMessageFunction(const std::function<int(const std::string&)>& pushMessage)
{
    m_pushMessage = pushMessage;
}

void SecurityConfigurationAssessment::SetGlobalWmExecFunction(int (*wmExecFunc)(char*, char**, int*, int, const char*))
{
    std::cout << "Setting global wm_exec function pointer." << std::endl;
    s_wmExecFunc = wmExecFunc;
}

int (*SecurityConfigurationAssessment::GetGlobalWmExecFunction())(char*, char**, int*, int, const char*)
{
    return s_wmExecFunc;
}

std::string SecurityConfigurationAssessment::GetCreateStatement() const
{
    std::string ret;
    ret += POLICY_SQL_STATEMENT;
    ret += CHECK_SQL_STATEMENT;

    return ret;
}

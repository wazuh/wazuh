#pragma once

#include <ifile_io_utils.hpp>
#include <ifilesystem_wrapper.hpp>
#include <sysInfoInterface.h>

#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <vector>

enum class RuleResult
{
    Invalid = -1,
    Found,
    NotFound
};

struct PolicyEvaluationContext
{
    std::string rule = {};
    std::optional<std::string> pattern = std::nullopt;
    bool isNegated = false;
    int commandsTimeout= 30;
    bool commandsEnabled = true;
};

class IRuleEvaluator
{
public:
    virtual ~IRuleEvaluator() = default;

    /// @brief Evaluates the rule
    /// @return Returns a RuleResult indicating if the rule was found or is invalid
    virtual RuleResult Evaluate() = 0;

    virtual const PolicyEvaluationContext& GetContext() const = 0;
};

class RuleEvaluator : public IRuleEvaluator
{
public:
    RuleEvaluator(PolicyEvaluationContext ctx, std::unique_ptr<IFileSystemWrapper> fileSystemWrapper);

    const PolicyEvaluationContext& GetContext() const override;

protected:
    std::unique_ptr<IFileSystemWrapper> m_fileSystemWrapper = nullptr;
    PolicyEvaluationContext m_ctx = {};
};

class FileRuleEvaluator : public RuleEvaluator
{
public:
    FileRuleEvaluator(PolicyEvaluationContext ctx,
                      std::unique_ptr<IFileSystemWrapper> fileSystemWrapper = nullptr,
                      std::unique_ptr<IFileIOUtils> fileUtils = nullptr);

    RuleResult Evaluate() override;

private:
    RuleResult CheckFileForContents();

    RuleResult CheckFileExistence();

    std::unique_ptr<IFileIOUtils> m_fileUtils = nullptr;
};

class CommandRuleEvaluator : public RuleEvaluator
{
public:
    struct ExecResult
    {
        std::string StdOut;
        std::string StdErr;
        int ExitCode;
    };

    /// @brief Function that takes a command and returns the output and error as a pair of strings.
    using CommandExecFunc = std::function<std::optional<ExecResult>(const std::string&)>;

    CommandRuleEvaluator(PolicyEvaluationContext ctx,
                         std::unique_ptr<IFileSystemWrapper> fileSystemWrapper = nullptr,
                         CommandExecFunc commandExecFunc = nullptr);

    RuleResult Evaluate() override;

private:
    CommandExecFunc m_commandExecFunc = nullptr;
};

class DirRuleEvaluator : public RuleEvaluator
{
public:
    DirRuleEvaluator(PolicyEvaluationContext ctx,
                     std::unique_ptr<IFileSystemWrapper> fileSystemWrapper,
                     std::unique_ptr<IFileIOUtils> fileUtils);

    RuleResult Evaluate() override;

private:
    RuleResult CheckDirectoryForContents();

    RuleResult CheckDirectoryExistence();

    std::unique_ptr<IFileIOUtils> m_fileUtils = nullptr;
};

class ProcessRuleEvaluator : public RuleEvaluator
{
public:
    using GetProcessesFunc = std::function<std::vector<std::string>()>;

    ProcessRuleEvaluator(PolicyEvaluationContext ctx,
                         std::unique_ptr<IFileSystemWrapper> fileSystemWrapper = nullptr,
                         std::unique_ptr<ISysInfo> sysInfo = nullptr,
                         GetProcessesFunc getProcesses = nullptr);

    RuleResult Evaluate() override;

private:
    std::unique_ptr<ISysInfo> m_sysInfo = nullptr;
    GetProcessesFunc m_getProcesses = nullptr;
};

/// @brief Subclass of RuleEvaluator that evaluates registry-related rules
class RegistryRuleEvaluator : public RuleEvaluator
{
public:
    using IsValidKeyFunc = std::function<bool(const std::string& rootKey)>;
    using EnumKeysFunc = std::function<std::vector<std::string>(const std::string& root)>;
    using EnumValuesFunc = std::function<std::vector<std::string>(const std::string& root)>;
    using GetValueFunc = std::function<std::optional<std::string>(const std::string& key, const std::string& value)>;

    /// @brief Constructor
    /// @param ctx Evaluation context
    /// @param isValidKey Function that returns true if the key is valid
    /// @param enumKeys Function that returns a vector of subkeys
    /// @param enumValues Function that returns a vector of values
    /// @param getValue Function that returns the value of a key
    RegistryRuleEvaluator(PolicyEvaluationContext ctx,
                          IsValidKeyFunc isValidKey = nullptr,
                          EnumKeysFunc enumKeys = nullptr,
                          EnumValuesFunc enumValues = nullptr,
                          GetValueFunc getValue = nullptr);

    /// @copydoc IRuleEvaluator::Evaluate
    RuleResult Evaluate() override;

private:
    /// @brief Checks if the key has the contents expected by the rule
    /// @return Returns a RuleResult with the result
    RuleResult CheckKeyForContents();

    /// @brief Checks if a Key exists
    /// @return Returns a RuleResult with the result
    RuleResult CheckKeyExistence();

    IsValidKeyFunc m_isValidKey = nullptr;
    EnumValuesFunc m_enumValues = nullptr;
    EnumKeysFunc m_enumKeys = nullptr;
    GetValueFunc m_getValue = nullptr;
};

class RuleEvaluatorFactory
{
public:
    static std::unique_ptr<IRuleEvaluator>
    CreateEvaluator(const std::string& input,
                    const int commandsTimeout,
                    const bool commandsEnabled,
                    std::unique_ptr<IFileSystemWrapper> fileSystemWrapper = nullptr,
                    std::unique_ptr<IFileIOUtils> fileUtils = nullptr,
                    std::unique_ptr<ISysInfo> sysInfo = nullptr);
};

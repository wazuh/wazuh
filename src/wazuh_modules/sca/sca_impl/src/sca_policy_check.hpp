#pragma once

#include <ifile_io_utils.hpp>
#include <ifilesystem_wrapper.hpp>
#include <sca_utils.hpp>
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
    NotFound,
    NotRun
};

struct RuleEvaluationResult
{
    RuleEvaluationResult(RuleResult r, const std::string& reasonValue = "", const std::string& sourceValue = "")
        : result(r)
        , reason(reasonValue)
        , source(sourceValue)
    {
    }

    RuleResult result;
    std::string reason;
    /// The rule as written in the policy, see PolicyEvaluationContext::source.
    std::string source;
};

struct PolicyEvaluationContext
{
    std::string rule = {};
    std::optional<std::string> pattern = std::nullopt;
    bool isNegated = false;
    int commandsTimeout = 30;
    bool commandsEnabled = true;
    sca::RegexEngineType regexEngine = sca::RegexEngineType::PCRE2;
    /// The rule as written in the policy, with policy variables already replaced, e.g.
    /// "not f:/etc/passwd -> r:^root". The same text as the check's entry in "rules".
    std::string source = {};
};

class IRuleEvaluator
{
    public:
        virtual ~IRuleEvaluator() = default;

        /// @brief Evaluates the rule
        /// @return Returns a RuleResult indicating if the rule was found or is invalid
        virtual RuleResult Evaluate() = 0;

        virtual const PolicyEvaluationContext& GetContext() const = 0;

        virtual std::string GetUnresolvedReason() const = 0;
};

class RuleEvaluator : public IRuleEvaluator
{
    public:
        RuleEvaluator(PolicyEvaluationContext ctx, std::unique_ptr<IFileSystemWrapper> fileSystemWrapper);

        const PolicyEvaluationContext& GetContext() const override;

        std::string GetUnresolvedReason() const override
        {
            return m_lastUnresolvedReason;
        }

    protected:
        std::unique_ptr<IFileSystemWrapper> m_fileSystemWrapper = nullptr;
        PolicyEvaluationContext m_ctx = {};
        std::string m_lastUnresolvedReason;
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
            bool TimedOut = false;
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

/// @brief Registry view a registry rule is evaluated against.
/// @details The agent runs as a 32-bit process on 64-bit Windows, where WOW64 redirects
///          parts of HKLM\\SOFTWARE to WOW6432Node unless a view is requested explicitly.
enum class RegistryView
{
    Bits64,
    Bits32
};

/// @brief Subclass of RuleEvaluator that evaluates registry-related rules
class RegistryRuleEvaluator : public RuleEvaluator
{
    public:
        using IsValidKeyFunc = std::function<bool(const std::string& rootKey, RegistryView view)>;
        using EnumKeysFunc = std::function<std::vector<std::string>(const std::string& root, RegistryView view)>;
        using EnumValuesFunc = std::function<std::vector<std::string>(const std::string& root, RegistryView view)>;
        using GetValueFunc =
            std::function<std::optional<std::string>(const std::string& key, const std::string& value, RegistryView view)>;

        /// @brief Constructor
        /// @param ctx Evaluation context
        /// @param isValidKey Function that returns true if the key exists in the given view
        /// @param enumKeys Function that returns the subkeys of a key in the given view
        /// @param enumValues Function that returns the value names of a key in the given view
        /// @param getValue Function that returns the data of a value in the given view
        RegistryRuleEvaluator(PolicyEvaluationContext ctx,
                              IsValidKeyFunc isValidKey = nullptr,
                              EnumKeysFunc enumKeys = nullptr,
                              EnumValuesFunc enumValues = nullptr,
                              GetValueFunc getValue = nullptr);

        /// @copydoc IRuleEvaluator::Evaluate
        /// @details The rule is evaluated against the 64-bit registry view and, unless it is found
        ///          there, against the 32-bit view. It is Found if either view finds it and Invalid
        ///          only if both views are Invalid. Negation is applied to that combined result.
        RuleResult Evaluate() override;

    private:
        /// @brief Checks if the key has the contents expected by the rule, ignoring negation
        /// @param view Registry view to look in
        /// @return Returns a RuleResult with the result
        RuleResult CheckKeyForContents(RegistryView view);

        /// @brief Checks if a Key exists, ignoring negation
        /// @param view Registry view to look in
        /// @return Returns a RuleResult with the result
        RuleResult CheckKeyExistence(RegistryView view);

        IsValidKeyFunc m_isValidKey = nullptr;
        EnumKeysFunc m_enumKeys = nullptr;
        EnumValuesFunc m_enumValues = nullptr;
        GetValueFunc m_getValue = nullptr;
};

namespace sca::win
{
    /// @brief Expands Win32 environment variables (e.g. "%PROGRAMFILES%\\foo")
    ///        in SCA rule inputs. Unknown %VAR% tokens are left literal.
    ///        Returns the input unchanged on failure.
    std::string ExpandEnvironmentVariables(const std::string& input);
}

class RuleEvaluatorFactory
{
    public:
        static std::unique_ptr<IRuleEvaluator>
        CreateEvaluator(const std::string& input,
                        const int commandsTimeout,
                        const bool commandsEnabled,
                        sca::RegexEngineType regexEngine = sca::RegexEngineType::PCRE2,
                        std::unique_ptr<IFileSystemWrapper> fileSystemWrapper = nullptr,
                        std::unique_ptr<IFileIOUtils> fileUtils = nullptr,
                        std::unique_ptr<ISysInfo> sysInfo = nullptr);
};

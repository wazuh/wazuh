#include <sca_policy_check.hpp>

#include <sca_utils.hpp>
#include <sca_impl.hpp>

#include <file_io_utils.hpp>
#include <filesystem_wrapper.hpp>
#include <stringHelper.h>
#include <sysInfo.hpp>
#include <sysInfoInterface.h>

#include "logging_helper.hpp"

// extern "C" {
// #include <wm_exec.h>
// }

#include <stack>
#include <stdexcept>

namespace
{
    template<typename Func>
    auto TryFunc(Func&& func) -> std::optional<decltype(func())>
    {
        try
        {
            return std::forward<Func>(func)();
        }
        catch (const std::exception&)
        {
            return std::nullopt;
        }
    }

    RuleResult FindContentInFile(const std::unique_ptr<IFileIOUtils>& fileUtils,
                                 const std::string& filePath,
                                 const std::string& pattern,
                                 const bool isNegated)
    {
        bool matchFound = false;

        if (sca::IsRegexOrNumericPattern(pattern))
        {
            const auto content = fileUtils->getFileContent(filePath);

            if (const auto patternMatch = sca::PatternMatches(content, pattern))
            {
                matchFound = patternMatch.value();
            }
            else
            {
                LoggingHelper::getInstance().log(LOG_DEBUG, "Invalid pattern '" + pattern + "' for file '" + filePath + "'");
                return RuleResult::Invalid;
            }
        }
        else
        {
            fileUtils->readLineByLine(filePath,
                                      [&pattern, &matchFound](const std::string& line)
                                      {
                                          if (line == pattern)
                                          {
                                              matchFound = true;
                                              return false;
                                          }
                                          return true;
                                      });
        }

        LoggingHelper::getInstance().log(LOG_DEBUG, "Pattern '" + pattern + "' " + (matchFound ? "was" : "was not") + " found in file '" + filePath + "'");
        return (matchFound != isNegated) ? RuleResult::Found : RuleResult::NotFound;
    }
} // namespace

RuleEvaluator::RuleEvaluator(PolicyEvaluationContext ctx,
                             std::unique_ptr<IFileSystemWrapper> fileSystemWrapper)
    : m_fileSystemWrapper(fileSystemWrapper ? std::move(fileSystemWrapper)
                                            : std::make_unique<file_system::FileSystemWrapper>())
    , m_ctx(std::move(ctx))
{
    if (m_ctx.rule.empty())
    {
        throw std::invalid_argument("Rule cannot be empty");
    }
}

const PolicyEvaluationContext& RuleEvaluator::GetContext() const
{
    return m_ctx;
}

FileRuleEvaluator::FileRuleEvaluator(PolicyEvaluationContext ctx,
                                     std::unique_ptr<IFileSystemWrapper> fileSystemWrapper,
                                     std::unique_ptr<IFileIOUtils> fileUtils)
    : RuleEvaluator(std::move(ctx), std::move(fileSystemWrapper))
    , m_fileUtils(std::move(fileUtils))
{
}

RuleResult FileRuleEvaluator::Evaluate()
{
    if (m_ctx.pattern)
    {
        return CheckFileForContents();
    }
    return CheckFileExistence();
}

RuleResult FileRuleEvaluator::CheckFileForContents()
{
    const auto pattern = *m_ctx.pattern; // NOLINT(bugprone-unchecked-optional-access)

    LoggingHelper::getInstance().log(LOG_DEBUG, "Processing file rule. Checking contents of file: '" + m_ctx.rule + "' against pattern:  " + pattern);

    if (TryFunc(
            [&]
            { return !m_fileSystemWrapper->exists(m_ctx.rule) || !m_fileSystemWrapper->is_regular_file(m_ctx.rule); })
            .value_or(false))
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, "File '" + m_ctx.rule + "' does not exist or is not a regular file");
        return RuleResult::Invalid;
    }

    return TryFunc([&] { return FindContentInFile(m_fileUtils, m_ctx.rule, pattern, m_ctx.isNegated); })
        .value_or(RuleResult::Invalid);
}

RuleResult FileRuleEvaluator::CheckFileExistence()
{
    auto result = RuleResult::NotFound;

    LoggingHelper::getInstance().log(LOG_DEBUG, "Processing file rule. Checking existence of file: '" + m_ctx.rule + "'");

    if (const auto fileOk = TryFunc(
            [&]
            { return m_fileSystemWrapper->exists(m_ctx.rule) && m_fileSystemWrapper->is_regular_file(m_ctx.rule); }))
    {
        if (fileOk.value())
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, "File '" + m_ctx.rule + "' exists");
            result = RuleResult::Found;
        }
        else
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, "File '" + m_ctx.rule + "' does not exist or is not a regular file");
        }
    }
    else
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, "An error occured and file rule '" + m_ctx.rule + "' could not be resolved");
        return RuleResult::Invalid;
    }

    return m_ctx.isNegated ? (result == RuleResult::Found ? RuleResult::NotFound : RuleResult::Found) : result;
}

CommandRuleEvaluator::CommandRuleEvaluator(PolicyEvaluationContext ctx,
                                           std::unique_ptr<IFileSystemWrapper> fileSystemWrapper,
                                           CommandExecFunc commandExecFunc)
    : RuleEvaluator(std::move(ctx), std::move(fileSystemWrapper))
{
    if (commandExecFunc)
    {
        m_commandExecFunc = std::move(commandExecFunc);
    }
    else
    {
        m_commandExecFunc = [timeout = ctx.commandsTimeout](const std::string& command) -> std::optional<ExecResult>
        {
            auto wmExecCallback = SecurityConfigurationAssessment::GetGlobalWmExecFunction();

            if (!wmExecCallback)
            {
                return std::nullopt;
            }

            char *cmdOutput = nullptr;
            int resultCode = 0;

            const auto wmExecResult = wmExecCallback(const_cast<char*>(command.c_str()), &cmdOutput, &resultCode, timeout, nullptr);

            ExecResult execResult;
            execResult.StdOut = cmdOutput ? std::string(cmdOutput) : "";
            execResult.StdErr = ""; // wm_exec doesn't provide stderr separately
            execResult.ExitCode = resultCode;

            if (cmdOutput)
            {
                free(cmdOutput);
            }

            if (wmExecResult == 0)
            {
                return execResult;
            }
            else
            {
                return std::nullopt;
            }
        };
    }
}

RuleResult CommandRuleEvaluator::Evaluate()
{
    LoggingHelper::getInstance().log(LOG_DEBUG, "Processing command rule: '" + m_ctx.rule + "'");

    if(!m_ctx.commandsEnabled)
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, "Policy is remote and remote commands are disabled. Skipping command rule.");
        return RuleResult::Invalid;
    }

    auto result = RuleResult::NotFound;

    if (!m_ctx.rule.empty())
    {
        if (auto execResult = m_commandExecFunc(m_ctx.rule))
        {
            if (m_ctx.pattern)
            {
                // Trim ending lines if any (command output may have trailing newlines)
                execResult->StdOut = Utils::trim(execResult->StdOut, "\n");
                execResult->StdErr = Utils::trim(execResult->StdErr, "\n");

                if (sca::IsRegexOrNumericPattern(*m_ctx.pattern))
                {
                    const auto outputPatternMatch = sca::PatternMatches(execResult->StdOut, *m_ctx.pattern);
                    const auto errorPatternMatch = sca::PatternMatches(execResult->StdErr, *m_ctx.pattern);

                    if (outputPatternMatch || errorPatternMatch)
                    {
                        result = outputPatternMatch.value_or(false) || errorPatternMatch.value_or(false)
                                     ? RuleResult::Found
                                     : RuleResult::NotFound;
                    }
                    else
                    {
                        LoggingHelper::getInstance().log(LOG_DEBUG, "Invalid pattern '" + *m_ctx.pattern + "' for command rule evaluation");
                        return RuleResult::Invalid;
                    }
                }
                else if (execResult->StdOut == m_ctx.pattern.value() || execResult->StdErr == m_ctx.pattern.value())
                {
                    result = RuleResult::Found;
                }
            }
            else
            {
                result = RuleResult::Found;
            }
        }
        else
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, "Command rule '" + m_ctx.rule + "' execution failed");
            return RuleResult::Invalid;
        }
    }
    else
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, "Command rule is empty");
    }

    LoggingHelper::getInstance().log(LOG_DEBUG, "Command rule evaluation result: " + m_ctx.rule + "' pattern '" + m_ctx.pattern.value_or("") + "' was " + (result == RuleResult::Found ? "found" : "not found"));

    return m_ctx.isNegated ? (result == RuleResult::Found ? RuleResult::NotFound : RuleResult::Found) : result;
}

DirRuleEvaluator::DirRuleEvaluator(PolicyEvaluationContext ctx,
                                   std::unique_ptr<IFileSystemWrapper> fileSystemWrapper,
                                   std::unique_ptr<IFileIOUtils> fileUtils)
    : RuleEvaluator(std::move(ctx), std::move(fileSystemWrapper))
    , m_fileUtils(std::move(fileUtils))
{
}

RuleResult DirRuleEvaluator::Evaluate()
{
    if (m_ctx.pattern)
    {
        return CheckDirectoryForContents();
    }
    return CheckDirectoryExistence();
}

RuleResult DirRuleEvaluator::CheckDirectoryForContents()
{
    LoggingHelper::getInstance().log(LOG_DEBUG,  "Processing directory rule:  '" + m_ctx.rule + "'");

    if (!TryFunc([&] { return m_fileSystemWrapper->exists(m_ctx.rule); }).value_or(false))
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, "Path '" + m_ctx.rule + "' does not exist");
        return RuleResult::Invalid;
    }

    auto resolved = TryFunc([&] { return m_fileSystemWrapper->canonical(m_ctx.rule); });
    if (!resolved)
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, "Directory '" + m_ctx.rule + "' could not be resolved");
        return RuleResult::Invalid;
    }
    const auto rootPath = *resolved;

    if (!TryFunc([&] { return m_fileSystemWrapper->is_directory(rootPath); }).value_or(false))
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, "Path '" + rootPath.string() + "' is not a directory");
        return RuleResult::Invalid;
    }

    const auto pattern = *m_ctx.pattern; // NOLINT(bugprone-unchecked-optional-access)

    std::stack<std::filesystem::path> dirs;
    dirs.emplace(rootPath);

    while (!dirs.empty())
    {
        const auto currentDir = dirs.top();
        dirs.pop();

        const auto filesOpt = TryFunc([&] { return m_fileSystemWrapper->list_directory(currentDir); });
        if (!filesOpt)
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, "Directory '" + currentDir.string() + "' could not be listed");
            return RuleResult::Invalid;
        }
        if (filesOpt->empty())
        {
            continue;
        }

        bool hadValue = false;
        const auto& files = *filesOpt;

        // Check if pattern is a regex
        const auto isRegex = sca::IsRegexPattern(pattern);

        // Check if pattern has content
        const auto content = sca::GetPattern(pattern);

        for (const auto& file : files)
        {
            if (const auto isSymlink = TryFunc([&] { return m_fileSystemWrapper->is_symlink(file); }))
            {
                if (isSymlink.value())
                {
                    continue;
                }
            }
            else
            {
                LoggingHelper::getInstance().log(LOG_DEBUG, "Symlink check failed for file '" + file.string() + "'");
                return RuleResult::Invalid;
            }

            if (const auto isDirectory = TryFunc([&] { return m_fileSystemWrapper->is_directory(file); }))
            {
                if (isDirectory.value())
                {
                    dirs.emplace(file);
                    continue;
                }
            }
            else
            {
                LoggingHelper::getInstance().log(LOG_DEBUG,  "Directory check failed for file '" + file.string() + "'");
                return RuleResult::Invalid;
            }

            if (isRegex)
            {
                const auto patternMatch = sca::PatternMatches(file.filename().string(), pattern);
                if (patternMatch.has_value())
                {
                    hadValue = true;
                    if (patternMatch.value())
                    {
                        LoggingHelper::getInstance().log(LOG_DEBUG, "Pattern '" + pattern + "' was found in directory '" + rootPath.string() + "'");
                        return m_ctx.isNegated ? RuleResult::NotFound : RuleResult::Found;
                    }
                }
            }
            else if (content.has_value())
            {
                const auto fileName = pattern.substr(0, pattern.find(" -> "));

                if (file.filename().string() == fileName)
                {
                    return TryFunc(
                               [&]
                               { return FindContentInFile(m_fileUtils, fileName, content.value(), m_ctx.isNegated); })
                        .value_or(RuleResult::Invalid);
                }
            }
            else
            {
                if (file.filename().string() == pattern)
                {
                    LoggingHelper::getInstance().log(LOG_DEBUG, "Pattern '" + pattern + "' was found in directory '" + rootPath.string() + "'");
                    return m_ctx.isNegated ? RuleResult::NotFound : RuleResult::Found;
                }
            }
        }

        if (isRegex && !hadValue)
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, "Invalid pattern '" + pattern + "' for directory '" + rootPath.string() + "'");
            return RuleResult::Invalid;
        }
    }

    LoggingHelper::getInstance().log(LOG_DEBUG, "Pattern '" + pattern + "' was not found in directory '" + rootPath.string() + "'");
    return m_ctx.isNegated ? RuleResult::Found : RuleResult::NotFound;
}

RuleResult DirRuleEvaluator::CheckDirectoryExistence()
{
    auto result = RuleResult::NotFound;

    LoggingHelper::getInstance().log(LOG_DEBUG, "Processing directory rule. Checking existence of directory: '" + m_ctx.rule + "'");

    if (const auto dirOk = TryFunc(
            [&] { return m_fileSystemWrapper->exists(m_ctx.rule) && m_fileSystemWrapper->is_directory(m_ctx.rule); }))
    {
        if (dirOk.value())
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, "Directory '" + m_ctx.rule + "' exists");
            result = RuleResult::Found;
        }
        else
        {
            LoggingHelper::getInstance().log(LOG_DEBUG, "Directory '" + m_ctx.rule + "' does not exist or is not a directory");
        }
    }
    else
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, "An error occured and file rule " + m_ctx.rule + " could not be resolved");
        return RuleResult::Invalid;
    }

    return m_ctx.isNegated ? (result == RuleResult::Found ? RuleResult::NotFound : RuleResult::Found) : result;
}

ProcessRuleEvaluator::ProcessRuleEvaluator(PolicyEvaluationContext ctx,
                                           std::unique_ptr<IFileSystemWrapper> fileSystemWrapper,
                                           std::unique_ptr<ISysInfo> sysInfo,
                                           GetProcessesFunc getProcesses)
    : RuleEvaluator(std::move(ctx), std::move(fileSystemWrapper))
    , m_sysInfo(std::move(sysInfo))
    , m_getProcesses(getProcesses ? std::move(getProcesses) : [this]()
                     {
                         std::vector<std::string> processNames;

                         m_sysInfo->processes(
                             [&processNames](nlohmann::json& procJson)
                             {
                                 if (procJson.contains("name") && procJson["name"].is_string())
                                 {
                                     processNames.emplace_back(procJson["name"]);
                                 }
                             });

                         return processNames;
                     })
{
}

RuleResult ProcessRuleEvaluator::Evaluate()
{
    LoggingHelper::getInstance().log(LOG_DEBUG, "Processing process rule: '" + m_ctx.rule + "'");

    auto result = RuleResult::NotFound;

    if (const auto processes = TryFunc([this] { return m_getProcesses(); }))
    {
        for (const auto& process : processes.value())
        {
            if (process == m_ctx.rule)
            {
                result = RuleResult::Found;
                break;
            }
        }
    }
    else
    {
        LoggingHelper::getInstance().log(LOG_DEBUG, "Process rule '" + m_ctx.rule + "' execution failed");
        return RuleResult::Invalid;
    }

    LoggingHelper::getInstance().log(LOG_DEBUG, "Process '" + m_ctx.rule + "' was " + (result == RuleResult::Found ? "found" : "not found"));
    return m_ctx.isNegated ? (result == RuleResult::Found ? RuleResult::NotFound : RuleResult::Found) : result;
}

std::unique_ptr<IRuleEvaluator>
RuleEvaluatorFactory::CreateEvaluator(const std::string& input,
                                      const int commandsTimeout,
                                      const bool commandsEnabled,
                                      std::unique_ptr<IFileSystemWrapper> fileSystemWrapper,
                                      std::unique_ptr<IFileIOUtils> fileUtils,
                                      std::unique_ptr<ISysInfo> sysInfo)
{
    if (!fileSystemWrapper)
    {
        fileSystemWrapper = std::make_unique<file_system::FileSystemWrapper>();
    }
    if (!fileUtils)
    {
        fileUtils = std::make_unique<file_io::FileIOUtils>();
    }
    if (!sysInfo)
    {
        sysInfo = std::make_unique<SysInfo>();
    }

    auto ruleInput = Utils::trim(input, " \t");
    auto isNegated = false;
    if (ruleInput.size() >= 4 && ruleInput.compare(0, 4, "not ") == 0)
    {
        isNegated = true;
        ruleInput = Utils::trim(ruleInput.substr(4), " \t");
    }

    const auto pattern = sca::GetPattern(ruleInput);
    if (pattern.has_value())
    {
        ruleInput = Utils::trim(ruleInput.substr(0, ruleInput.find("->")), " \t");
    }

    const auto ruleTypeAndValue = sca::ParseRuleType(ruleInput);
    if (!ruleTypeAndValue.has_value())
    {
        return nullptr;
    }

    const auto [ruleType, cleanedRule] = ruleTypeAndValue.value();

    const PolicyEvaluationContext ctx {cleanedRule, pattern, isNegated, commandsTimeout, commandsEnabled};

    switch (ruleType)
    {
        case sca::WM_SCA_TYPE_FILE:
            return std::make_unique<FileRuleEvaluator>(ctx, std::move(fileSystemWrapper), std::move(fileUtils));
#ifdef _WIN32
        case sca::WM_SCA_TYPE_REGISTRY: return std::make_unique<RegistryRuleEvaluator>(ctx);
#endif
        case sca::WM_SCA_TYPE_PROCESS:
            return std::make_unique<ProcessRuleEvaluator>(ctx, std::move(fileSystemWrapper), std::move(sysInfo));
        case sca::WM_SCA_TYPE_DIR:
            return std::make_unique<DirRuleEvaluator>(ctx, std::move(fileSystemWrapper), std::move(fileUtils));
        case sca::WM_SCA_TYPE_COMMAND: return std::make_unique<CommandRuleEvaluator>(ctx, std::move(fileSystemWrapper));
        default: return nullptr;
    }
}

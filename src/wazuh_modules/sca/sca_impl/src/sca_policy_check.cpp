#include <sca_policy_check.hpp>

#include <sca_utils.hpp>

#include <file_io_utils.hpp>
#include <filesystem_wrapper.hpp>
// #include <logger.hpp>
#include <stringHelper.h>
#include <sysInfo.hpp>
#include <sysInfoInterface.h>

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
                // LogDebug("Invalid pattern '{}' for file '{}'", pattern, filePath);
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

        // LogDebug("Pattern '{}' {} found in file '{}'", pattern, matchFound ? "was" : "was not", filePath);
        return (matchFound != isNegated) ? RuleResult::Found : RuleResult::NotFound;
    }
} // namespace

RuleEvaluator::RuleEvaluator(PolicyEvaluationContext ctx, std::unique_ptr<IFileSystemWrapper> fileSystemWrapper)
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

    // LogDebug("Processing file rule. Checking contents of file: '{}' against pattern '{}'", m_ctx.rule, pattern);

    if (TryFunc(
            [&]
            { return !m_fileSystemWrapper->exists(m_ctx.rule) || !m_fileSystemWrapper->is_regular_file(m_ctx.rule); })
            .value_or(false))
    {
        // LogDebug("File '{}' does not exist or is not a regular file", m_ctx.rule);
        return RuleResult::Invalid;
    }

    return TryFunc([&] { return FindContentInFile(m_fileUtils, m_ctx.rule, pattern, m_ctx.isNegated); })
        .value_or(RuleResult::Invalid);
}

RuleResult FileRuleEvaluator::CheckFileExistence()
{
    auto result = RuleResult::NotFound;

    // LogDebug("Processing file rule. Checking existence of file: '{}'", m_ctx.rule);

    if (const auto fileOk = TryFunc(
            [&]
            { return m_fileSystemWrapper->exists(m_ctx.rule) && m_fileSystemWrapper->is_regular_file(m_ctx.rule); }))
    {
        if (fileOk.value())
        {
            // LogDebug("File '{}' exists", m_ctx.rule);
            result = RuleResult::Found;
        }
        else
        {
            // LogDebug("File '{}' does not exist or is not a file", m_ctx.rule);
        }
    }
    else
    {
        // LogDebug("An error occured and file rule '{}' could not be resolved", m_ctx.rule);
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
        m_commandExecFunc = [](const std::string& command) -> std::optional<ExecResult>
        {
            // char *cmdOutput = nullptr;
            // int resultCode = 0;

            // const int timeoutSeconds = 30;
            // std::string mutableCommand = command;

            // const auto wmExecResult = wm_exec(const_cast<char*>(mutableCommand.c_str()), &cmdOutput, &resultCode, timeoutSeconds, nullptr);

            // ExecResult execResult;
            // execResult.StdOut = cmdOutput ? std::string(cmdOutput) : "";
            // execResult.StdErr = ""; // wm_exec doesn't provide stderr separately
            // execResult.ExitCode = resultCode;

            // if (cmdOutput)
            // {
            //     free(cmdOutput);
            // }

            // if (wmExecResult == 0)
            // {
            //     return execResult;
            // }
            // else
            // {
                return std::nullopt;
            // }
        };
    }
}

RuleResult CommandRuleEvaluator::Evaluate()
{
    // LogDebug("Processing command rule: '{}'", m_ctx.rule);

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
                        // LogDebug("Invalid pattern '{}' for command rule evaluation", *m_ctx.pattern);
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
            // LogDebug("Command rule '{}' execution failed", m_ctx.rule);
            return RuleResult::Invalid;
        }
    }
    else
    {
        // LogDebug("Command rule is empty");
    }

    // LogDebug("Command rule '{}' pattern '{}' {} found",
            //  m_ctx.rule,
            //  m_ctx.pattern.value_or(""),
            //  result == RuleResult::Found ? "was" : "was not");

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
    // LogDebug("Processing directory rule: '{}'", m_ctx.rule);

    if (!TryFunc([&] { return m_fileSystemWrapper->exists(m_ctx.rule); }).value_or(false))
    {
        // LogDebug("Path '{}' does not exist", m_ctx.rule);
        return RuleResult::Invalid;
    }

    auto resolved = TryFunc([&] { return m_fileSystemWrapper->canonical(m_ctx.rule); });
    if (!resolved)
    {
        // LogDebug("Directory '{}' could not be resolved", m_ctx.rule);
        return RuleResult::Invalid;
    }
    const auto rootPath = *resolved;

    if (!TryFunc([&] { return m_fileSystemWrapper->is_directory(rootPath); }).value_or(false))
    {
        // LogDebug("Path '{}' is not a directory", rootPath.string());
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
            // LogDebug("Directory '{}' could not be listed", currentDir.string());
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
                // LogDebug("Symlink check failed for file '{}'", file.string());
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
                // LogDebug("Directory check failed for file '{}'", file.string());
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
                        // LogDebug("Pattern '{}' was found in directory '{}'", pattern, rootPath.string());
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
                    // LogDebug("Pattern '{}' was found in directory '{}'", pattern, rootPath.string());
                    return m_ctx.isNegated ? RuleResult::NotFound : RuleResult::Found;
                }
            }
        }

        if (isRegex && !hadValue)
        {
            // LogDebug("Invalid pattern '{}' for directory '{}'", pattern, rootPath.string());
            return RuleResult::Invalid;
        }
    }

    // LogDebug("Pattern '{}' was not found in directory '{}'", pattern, rootPath.string());
    return m_ctx.isNegated ? RuleResult::Found : RuleResult::NotFound;
}

RuleResult DirRuleEvaluator::CheckDirectoryExistence()
{
    auto result = RuleResult::NotFound;

    // LogDebug("Processing directory rule. Checking existence of directory: '{}'", m_ctx.rule);

    if (const auto dirOk = TryFunc(
            [&] { return m_fileSystemWrapper->exists(m_ctx.rule) && m_fileSystemWrapper->is_directory(m_ctx.rule); }))
    {
        if (dirOk.value())
        {
            // LogDebug("Directory '{}' exists", m_ctx.rule);
            result = RuleResult::Found;
        }
        else
        {
            // LogDebug("Directory '{}' does not exist or is not a directory", m_ctx.rule);
        }
    }
    else
    {
        // LogDebug("An error occured and file rule '{}' could not be resolved", m_ctx.rule);
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
    // LogDebug("Processing process rule: '{}'", m_ctx.rule);

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
        // LogDebug("Process rule '{}' execution failed", m_ctx.rule);
        return RuleResult::Invalid;
    }

    // LogDebug("Process '{}' {} found", m_ctx.rule, result == RuleResult::Found ? "was" : "was not");
    return m_ctx.isNegated ? (result == RuleResult::Found ? RuleResult::NotFound : RuleResult::Found) : result;
}

std::unique_ptr<IRuleEvaluator>
RuleEvaluatorFactory::CreateEvaluator(const std::string& input,
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

    const PolicyEvaluationContext ctx {cleanedRule, pattern, isNegated};

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

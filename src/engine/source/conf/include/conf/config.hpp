#ifndef _CONFIG_HPP
#define _CONFIG_HPP

#include <CLI/CLI.hpp>

#include <conf/iconfig.hpp>

namespace conf
{
class Config : public IConfig
{
private:
    CLI::App& m_subCommand;

    std::any getImplementation(const std::string& key) const override
    {
        return m_subCommand.get_option(key)->as<std::any>();
    }
};
} // namespace conf

#endif // _CONFIG_HPP

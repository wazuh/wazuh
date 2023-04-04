#ifndef _CMD_START_HPP
#define _CMD_START_HPP

#include <memory>

#include <CLI/CLI.hpp>

#include <conf/cliconf.hpp>
#include <conf/iconf.hpp>

namespace cmd::server
{

using ConfHandler = std::shared_ptr<conf::IConf<conf::CliConf>>;

void runStart(ConfHandler confManager);

void configure(CLI::App_p app);

} // namespace cmd::server

#endif // _CMD_START_HPP

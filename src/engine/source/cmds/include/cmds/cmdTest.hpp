#ifndef _CMD_TEST_HPP
#define _CMD_TEST_HPP

#include <string>
#include <vector>

namespace cmd
{

void test(const std::string& kvdbPath,
          const std::string& fileStorage,
          const std::string& environment,
          int debugLevel,
          bool traceAll,
          const std::vector<std::string>& assetTrace,
          int protocolQueue,
          const std::string& protocolLocation);
} // namespace cmd

#endif // _CMD_TEST_HPP

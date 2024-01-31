#include <gtest/gtest.h>

#include <handler.hpp>

namespace
{
auto maxmindDbPath = "/root/repos/wazuh/src/engine/test/source/zz_cpp_test/maxmind/GeoLite2-City.mmdb";
}

TEST(MMDBHandlerTest, open)
{
    mmdb::MMDBHandler mmdbHandler {maxmindDbPath};

    auto err = mmdbHandler.open();
    EXPECT_FALSE(err.has_value());

    auto result = mmdbHandler.lookup("181.96.193.10");
    // auto result = mmdbHandler.lookup("1.1.1.1");
    // auto result = mmdbHandler.lookup("8.8.4.4");

    EXPECT_TRUE(result->hasData());
    std::cout << base::getResponse<std::string>(result->getString("city.names.en")) << "\n";
    std::cout << std::to_string(base::getResponse<uint32_t>(result->getUint32("city.geoname_id"))) << "\n";
    std::cout << std::to_string(base::getResponse<double>(result->getDouble("location.latitude"))) << "\n";
    std::cout << std::to_string(base::getResponse<double>(result->getDouble("location.longitude"))) << "\n";

    std::cout << result->mmDump().prettyStr() << "\n";
    std::cout << base::getResponse<json::Json>(result->getAsJson("location.time_zone")).prettyStr() << "\n";
    std::cout << base::getResponse<json::Json>(result->getAsJson("location.longitude")).prettyStr() << "\n";
    std::cout << base::getResponse<json::Json>(result->getAsJson("location.accuracy_radius")).prettyStr() << "\n";
    mmdbHandler.close();
}

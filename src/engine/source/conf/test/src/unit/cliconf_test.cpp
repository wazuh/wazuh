#include <conf/cliconf.hpp>
#include <gtest/gtest.h>

#include <cstdio>
#include <filesystem>
#include <fstream>

TEST(CliConfTest, Builds)
{
    CLI::App_p app = std::make_shared<CLI::App>("Test");
    ASSERT_NO_THROW(conf::CliConf confManager(app));
}

TEST(CliConfTest, GetOption)
{
    CLI::App_p app = std::make_shared<CLI::App>("Test");
    app->add_option("--test", "Test option")->default_val("default");
    conf::CliConf confManager(app);
    std::string got;
    ASSERT_NO_THROW(got = confManager.get<std::string>("test"));
    ASSERT_EQ(got, "default");
}

TEST(CliConfTest, GetOptionBadKey)
{
    CLI::App_p app = std::make_shared<CLI::App>("Test");
    app->add_option("--test", "Test option")->default_val("default");
    conf::CliConf confManager(app);
    std::string got;
    ASSERT_THROW(got = confManager.get<std::string>("bad"), std::runtime_error);
}

TEST(CliConfTest, GetOptionBadType)
{
    CLI::App_p app = std::make_shared<CLI::App>("Test");
    app->add_option("--test", "Test option")->default_val("default");
    conf::CliConf confManager(app);
    int got;
    ASSERT_THROW(got = confManager.get<int>("test"), std::runtime_error);
}

// Subcommand server is hardcoded in CliConf
TEST(CliConfTest, GetConfiguration)
{
    CLI::App_p app = std::make_shared<CLI::App>("Test");
    auto sub = app->add_subcommand("server", "Server subcommand");
    sub->add_option("--test", "Test option")->default_val("default");

    auto fmtr = app->get_subcommand("server")->get_config_formatter();
    auto expected = fmtr->to_config(app->get_subcommand("server"), true, true, "server.");

    conf::CliConf confManager(app);
    std::string got;
    ASSERT_NO_THROW(got = confManager.getConfiguration());
    ASSERT_EQ(got, expected);
}

TEST(CliConfTest, Put)
{
    CLI::App_p app = std::make_shared<CLI::App>("Test");
    std::string testVar;
    app->add_option("--test", testVar, "Test option")->default_val("default");
    conf::CliConf confManager(app);
    ASSERT_NO_THROW(confManager.put("test", "new"));
    std::string got;
    ASSERT_NO_THROW(got = confManager.get<std::string>("test"));
    ASSERT_EQ(got, "new");
}

TEST(CliConfTest, PutBadKey)
{
    CLI::App_p app = std::make_shared<CLI::App>("Test");
    std::string testVar;
    app->add_option("--test", testVar, "Test option")->default_val("default");
    conf::CliConf confManager(app);
    ASSERT_THROW(confManager.put("bad", "new"), std::runtime_error);
}

TEST(CliConfTest, PutBadValue)
{
    CLI::App_p app = std::make_shared<CLI::App>("Test");
    std::string testVar;
    app->add_option("--test", testVar, "Test option")->default_val("good")->check(CLI::IsMember({"good"}));
    conf::CliConf confManager(app);
    ASSERT_THROW(confManager.put("test", "bad"), std::runtime_error);
}

TEST(CliConfTest, SaveConfigDefLocation)
{
    std::FILE* tmpf = std::tmpfile();
    auto tmpPath = std::filesystem::read_symlink(std::filesystem::path("/proc/self/fd") / std::to_string(fileno(tmpf)));

    CLI::App_p app = std::make_shared<CLI::App>("Test");
    auto sub = app->add_subcommand("server", "Server subcommand");
    sub->add_option("--test", "Test option")->default_val("default");
    app->set_config("--config", tmpPath.string(), "Config file");

    auto expected = app->get_subcommand("server")->get_config_formatter()->to_config(
                        app->get_subcommand("server"), true, true, "server.")
                    + "\n";

    conf::CliConf confManager(app);
    ASSERT_NO_THROW(confManager.saveConfiguration());

    std::ifstream ifs(tmpPath);
    std::string got((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));

    ifs.close();
    std::fclose(tmpf);

    ASSERT_EQ(got, expected);
}

TEST(CliConfTest, SaveConfigCustomLocation)
{
    std::FILE* tmpf = std::tmpfile();
    auto tmpPath = std::filesystem::read_symlink(std::filesystem::path("/proc/self/fd") / std::to_string(fileno(tmpf)));

    CLI::App_p app = std::make_shared<CLI::App>("Test");
    auto sub = app->add_subcommand("server", "Server subcommand");
    sub->add_option("--test", "Test option")->default_val("default");
    app->set_config("--config", "/tmp/default.ini", "Config file");

    auto expected = app->get_subcommand("server")->get_config_formatter()->to_config(
                        app->get_subcommand("server"), true, true, "server.")
                    + "\n";

    conf::CliConf confManager(app);
    ASSERT_NO_THROW(confManager.saveConfiguration(tmpPath));

    std::ifstream ifs(tmpPath);
    std::string got((std::istreambuf_iterator<char>(ifs)), (std::istreambuf_iterator<char>()));

    ifs.close();
    std::fclose(tmpf);

    ASSERT_EQ(got, expected);
}

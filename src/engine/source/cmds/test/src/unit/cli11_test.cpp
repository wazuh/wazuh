#include <gtest/gtest.h>

#include <CLI/CLI.hpp>

TEST(CLITEST, basicTest)
{
    CLI::App app {"App description"};
    auto conf = app.set_config("--config", "/tmp/config.toml");

    const char* argv[] = {"./appName"};
    int argc = sizeof(argv) / sizeof(char*);
    try
    {
        // subcommand->parse((argc), (argv));
        (app).parse((argc), (argv));
        // std::cout << app.config_to_str(true, true) << std::endl;
    }
    catch (const CLI::ParseError& e)
    {
        // subcommand->exit(e);
        app.exit(e);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    std::cout << "Conf path: " << conf->as<std::string>() << std::endl;

    conf->clear();
    conf->add_result("22");

    std::cout << "Modified Conf path: " << conf->as<std::string>() << std::endl;
}

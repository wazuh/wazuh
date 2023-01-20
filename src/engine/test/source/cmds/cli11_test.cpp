#include <gtest/gtest.h>

#include <CLI/CLI.hpp>


TEST(CLITEST, basicTest)
{
    CLI::App app {"App description"};
    std::vector<int> n;
    auto baseOpt = app.add_option("--option0",n, "Base option");
    auto a = baseOpt->get_type_name();


    const char* argv[] = {"./appName", "--option0", "1"};
    int argc = sizeof(argv) / sizeof(char*);
    try
    {
        (app).parse((argc), (argv));
        std::cout << app.config_to_str(true, true) << std::endl;
    }
    catch (const CLI::ParseError& e)
    {
        app.exit(e);
    }
    catch (const std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
}

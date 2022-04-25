#include <iostream>
#include <iterator>
#include <stdio.h>

#include <yaml-cpp/yaml.h>

#include <hlp/hlp.hpp>

static bool
printAny(std::string const& name, std::any const& anyVal)
{
    auto& type = anyVal.type();
    if (type == typeid(void))
    {
        printf("%30s | %s\n", name.c_str(), "*void*");
    }
    else if (type == typeid(long))
    {
        printf("%30s | %lu\n", name.c_str(), std::any_cast<long>(anyVal));
    }
    else if (type == typeid(int))
    {
        printf("%30s | %d\n", name.c_str(), std::any_cast<int>(anyVal));
    }
    else if (type == typeid(unsigned))
    {
        printf("%30s | %u\n", name.c_str(), std::any_cast<unsigned>(anyVal));
    }
    else if (type == typeid(float))
    {
        printf("%30s | %f\n", name.c_str(), std::any_cast<float>(anyVal));
    }
    else if (type == typeid(double))
    {
        printf("%30s | %lf\n", name.c_str(), std::any_cast<double>(anyVal));
    }
    else if (type == typeid(std::string))
    {
        printf("%30s | %s\n",
               name.c_str(),
               std::any_cast<std::string>(anyVal).c_str());
    }
    else if (type == typeid(hlp::JsonString))
    {
        printf("%30s | %s\n",
               name.c_str(),
               std::any_cast<hlp::JsonString>(anyVal).jsonString.c_str());
    }
    else
    {
        // ASSERT
        return false;
    }
    return true;
}

int main(int argc, char *argv[])
{
    std::vector<std::string> logql_expressions = {};
    std::vector<std::string> events = {};
    if (argc < 2)
    {
        printf("Usage:\n");
        printf(" %s  \"FILENAME\"\n", argv[0]);
        printf(" %s  \"LOGQL_EXPRESSION\" \"EVENT\"", argv[0]);
    }
    else if (argc == 2)
    {
        try
        {
            YAML::Node inputs = YAML::LoadFile(argv[1]);
            for (auto input : inputs)
            {
                logql_expressions.emplace_back(
                    input["logql_expression"].as<std::string>());
                events.emplace_back(input["event"].as<std::string>());
            }
        }
        catch (const std::exception &e)
        {
            printf("Error reading file %s. Error: %s\n", argv[1], e.what());
            return 0;
        }
    }
    else if (argc == 3)
    {
        logql_expressions.emplace_back(argv[1]);
        events.emplace_back(argv[2]);
    }
    else
    {
        printf("Error, too many arguments\n");
    }

    auto exp_it = logql_expressions.begin();
    auto event_it = events.begin();
    while (exp_it != logql_expressions.end() && event_it != events.end())
    {
        auto parseOp = hlp::getParserOp(exp_it->c_str());
        ParseResult result;
        bool ret = parseOp(event_it->c_str(), result);

        printf("----------\n");
        printf("LOGQL_EXPRESSION:\n");
        printf("%s\n", exp_it->c_str());
        printf("EVENT:\n");
        printf("%s\n", event_it->c_str());
        printf("RESULT:\n");
        printf("%30s | %s\n", "Key", "Val");
        printf("-------------------------------|------------\n");
        for (auto const &r : result)
        {
            printAny(r.first, r.second);
        }
        printf("\n\n");
        exp_it++;
        event_it++;
    }

    return 0;
}

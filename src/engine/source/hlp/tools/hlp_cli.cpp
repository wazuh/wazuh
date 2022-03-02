#include <stdio.h>
#include <iostream>
#include <iterator>
#include <hlp/hlp.hpp>
#include <yaml-cpp/yaml.h>

int main(int argc, char * argv[])
{
    std::vector<std::string> logql_expressions = {};
    std::vector<std::string> events = {};
    if (argc < 2) {
        printf("Usage:\n");
        printf(" %s  \"FILENAME\"\n", argv[0]);
        printf(" %s  \"LOGQL_EXPRESSION\" \"EVENT\"", argv[0]);
    }
    else if (argc == 2) {
        try {
            YAML::Node inputs = YAML::LoadFile(argv[1]);
            for(auto input : inputs){
                logql_expressions.emplace_back(input["logql_expression"].as<std::string>());
                events.emplace_back(input["event"].as<std::string>());
            }
        }
        catch (const std::exception & e) {
            printf("Error reading file %s. Error: %s\n", argv[1], e.what());
            return 0;
        }
    }
    else if (argc == 3) {
        logql_expressions.emplace_back(argv[1]);
        events.emplace_back(argv[2]);
    }
    else {
        printf("Error, too many arguments\n");
    }

    auto exp_it = logql_expressions.begin();
    auto event_it = events.begin();
    while(exp_it != logql_expressions.end() && event_it != events.end()) {
        auto parseOp = getParserOp(exp_it->c_str());
        auto result = parseOp(event_it->c_str());

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
            printf("%30s | %s\n", r.first.c_str(), r.second.c_str());
        }
        printf("\n\n");
        exp_it++;
        event_it++;
    }

    return 0;
}

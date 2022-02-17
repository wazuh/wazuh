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
        std::cout << "Usage:" << std::endl;
        std::cout << " "<< argv[0] << " \"FILENAME\"" << std::endl;
        std::cout << " "<< argv[0] << " \"LOGQL_EXPRESSION\" \"EVENT\"" << std::endl;
    }
    else if (argc < 3) {
        try {
            YAML::Node inputs = YAML::LoadFile(argv[1]);
            for(auto input : inputs){
                logql_expressions.emplace_back(input["logql_expression"].as<std::string>());
                events.emplace_back(input["event"].as<std::string>());
            }
        }
        catch (const std::exception & e) {
            std::cout << "Error reading file " << argv[1] << ".Error: " << e.what() << std::endl;
            return 0;
        }
    }
    else if (argc >= 3) {
        logql_expressions.emplace_back(argv[1]);
        events.emplace_back(argv[2]);
    }

    auto exp_it = logql_expressions.begin();
    auto event_it = events.begin();
    while(exp_it != logql_expressions.end() && event_it != events.end()) {
        auto parseOp = getParserOp(exp_it->c_str());
        auto result = parseOp(event_it->c_str());

        std::cout << "----------" << std::endl;
        std::cout << "LOGQL_EXPRESSION:" << std::endl;
        std::cout << *exp_it << std::endl;
        std::cout << "EVENT:" << std::endl;
        std::cout << *event_it << std::endl;
        std::cout << "RESULT:" << std::endl;
        for(auto it = result.cbegin(); it != result.cend(); ++it)
        {
            std::cout << it->first << " " << it->second << std::endl;
        }
        std::cout << "----------" << std::endl << std::endl;
        exp_it++;
        event_it++;
    }

    return 0;
}
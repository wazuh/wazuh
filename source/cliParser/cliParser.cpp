#include <algorithm>
#include <chrono>
#include <iostream>
#include <string>
#include <thread>

#include "cliParser.hpp"

using namespace std;

namespace cliparser
{
    
CliParser::CliParser(int argc, char *argv[]){
    parse(argc,argv);
}

void CliParser::parse(int argc, char *argv[]){
    argparse::ArgumentParser serverParser("server");
    serverParser.add_argument("--endpoint")
        .help("Endpoint configuration string")
        .required();

    serverParser.add_argument("--file_storage")
        .help("Path to storage folder")
        .required();

    try{
        serverParser.parse_args(argc, argv);
    }
    catch (const std::runtime_error& err) {
        std::cerr << err.what() << std::endl;
        cerr << serverParser;
    }

    m_endpoint_config = serverParser.get("--endpoint");
    m_storage_path = serverParser.get("--file_storage");
}

string CliParser::getEndpointConfig(){
    return m_endpoint_config;
}

string CliParser::getStoragePath(){
    return m_storage_path;
}

}

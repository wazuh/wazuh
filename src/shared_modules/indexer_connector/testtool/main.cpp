#include <indexerConnector.hpp>
#include <iostream>

int main()
{
    IndexerConnector indexerConnector(R"(
    {
        "servers": [
            "http://localhost:9200",
            "http://localhost:9300"
        ],
        "database_path": "/tmp/indexerConnector"
    })"_json);

    indexerConnector.publish(R"(
    {
        "type": "test",
        "data": {
            "message": "Hello world!"
        }
    })");

    indexerConnector.publish(R"(
    {
        "type": "test",
        "data": {
            "message": "World hello!"
        }
    })");

    // \cond
    std::this_thread::sleep_for(std::chrono::seconds(5));
    // \endcond

    return 0;
}

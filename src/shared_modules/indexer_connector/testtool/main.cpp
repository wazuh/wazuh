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
        "databasePath": "/tmp/indexerConnector"
    })"_json);

    indexerConnector.publish(R"(
    {
        "type": "test-index",
        "data": {
            "message": "Hello world!"
        },
        "id": "1",
        "operation": ""
    })");

    indexerConnector.publish(R"(
    {
        "type": "test-index",
        "data": {
            "message": "World hello!"
        },
        "id": "3",
        "operation": ""
    })");

    // \cond
    std::this_thread::sleep_for(std::chrono::seconds(5));
    // \endcond

    return 0;
}

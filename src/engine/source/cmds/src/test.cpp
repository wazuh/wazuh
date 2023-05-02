#include "cmds/test.hpp"

#include <cmds/apiclnt/client.hpp>
#include <cmds/details/stackExecutor.hpp>
#include <eMessages/tests.pb.h>

#include "defaultSettings.hpp"
#include "utils.hpp"

namespace cmd::test
{

namespace eTest = ::com::wazuh::api::engine::test;
namespace eEngine = ::com::wazuh::api::engine;

void run(std::shared_ptr<apiclnt::Client> client, const Options& options)
{
    using RequestType = eTest::Run_Request;
    using ResponseType = eTest::Run_Response;
    const std::string command {"test.resource/run"};

    RequestType eRequest;
    eRequest.set_kvdbpath(options.kvdbPath);
    eRequest.set_filestorage(options.fileStorage);
    eRequest.set_policy(options.policy);
    eRequest.set_loglevel(options.logLevel);
    eRequest.set_debuglevel(options.debugLevel);
    eRequest.set_protocolqueue(std::to_string(options.protocolQueue));
    eRequest.set_protocollocation(options.protocolLocation);

    // Call the API
    const auto request = utils::apiAdapter::toWazuhRequest<RequestType>(command, details::ORIGIN_NAME, eRequest);
    const auto response = client->send(request);
    const auto eResponse = utils::apiAdapter::fromWazuhResponse<ResponseType>(response);

    // Print value as json
    const auto& value = eResponse.value();
    const auto json = eMessage::eMessageToJson<google::protobuf::Value>(value);
    std::cout << std::get<std::string>(json) << std::endl;
}

void configure(CLI::App_p app)
{
    auto logtestApp = app->add_subcommand("test", "Utility to test the ruleset.");
    auto options = std::make_shared<Options>();

    logtestApp->add_option("-a, --api_socket", options->apiEndpoint, "engine api address")
        ->default_val(ENGINE_SRV_API_SOCK);
    const auto client = std::make_shared<apiclnt::Client>(options->apiEndpoint);

    // KVDB path
    logtestApp->add_option("-k, --kvdb_path", options->kvdbPath, "Sets the path to the KVDB folder.")
        ->default_val(ENGINE_KVDB_TEST_PATH)
        ->check(CLI::ExistingDirectory);

    // File storage
    logtestApp
        ->add_option("-f, --file_storage",
                     options->fileStorage,
                     "Sets the path to the folder where the assets are located (store).")
        ->default_val(ENGINE_STORE_PATH)
        ->check(CLI::ExistingDirectory);

    // Policy
    logtestApp->add_option("--policy", options->policy, "Name of the policy to be used.")
        ->default_val(ENGINE_DEFAULT_POLICY);

    // Protocol queue
    logtestApp
        ->add_option(
            "-q, --protocol_queue", options->protocolQueue, "Event protocol queue identifier (a single character).")
        ->default_val(ENGINE_PROTOCOL_QUEUE);

    // Protocol location
    logtestApp->add_option("--protocol_location", options->protocolLocation, "Protocol location.")
        ->default_val(ENGINE_PROTOCOL_LOCATION);

    // Log level
    logtestApp->add_option("-l, --log_level", options->logLevel, "Sets the logging level.")
        ->default_val(ENGINE_LOG_LEVEL)
        ->check(CLI::IsMember({"trace", "debug", "info", "warning", "error", "critical", "off"}));

    // Debug levels
    auto debug = logtestApp->add_flag("-d, --debug",
                                      options->debugLevel,
                                      "Enable debug mode [0-3]. Flag can appear multiple times. "
                                      "No flag[0]: No debug, d[1]: Asset history, dd[2]: 1 + "
                                      "Full tracing, ddd[3]: 2 + detailed parser trace.");

    // Trace
    logtestApp
        ->add_option("-t, --trace",
                     options->assetTrace,
                     "List of specific assets to be traced, separated by commas. By "
                     "default traces every asset. This only works "
                     "when debug=2.")
        ->needs(debug);

    // Register callback
    logtestApp->callback([options, client]() { run(client, *options); });
}
} // namespace cmd::test

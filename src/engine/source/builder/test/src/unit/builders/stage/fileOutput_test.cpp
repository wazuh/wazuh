#include "builders/baseBuilders_test.hpp"
#include "builders/stage/fileOutput.hpp"

using namespace builder::builders;

namespace stagebuildtest
{
INSTANTIATE_TEST_SUITE_P(Builders,
                         StageBuilderTest,
                         testing::Values(StageT(R"([])", fileOutputBuilder, FAILURE()),
                                         StageT(R"("notObject")", fileOutputBuilder, FAILURE()),
                                         StageT(R"(1)", fileOutputBuilder, FAILURE()),
                                         StageT(R"(null)", fileOutputBuilder, FAILURE()),
                                         StageT(R"(true)", fileOutputBuilder, FAILURE()),
                                         StageT(R"({})", fileOutputBuilder, FAILURE()),
                                         StageT(R"({"key": "val", "key2": "val2"})", fileOutputBuilder, FAILURE()),
                                         StageT(R"({"path": 1})", fileOutputBuilder, FAILURE()),
                                         StageT(R"({"path": "///"})", fileOutputBuilder, FAILURE()),
                                         StageT(R"({"path": "/tmp/path"})",
                                                fileOutputBuilder,
                                                SUCCESS(base::Term<base::EngineOp>::create("write.output(/tmp/path)",
                                                                                           {})))),
                         testNameFormatter<StageBuilderTest>("FileOutput"));
} // namespace stagebuildtest

namespace fileoutputtest
{
auto messageStr = R"({
    "event": {
        "original": "::1 - - [26/Dec/2016:16:16:29 +0200] \"GET /favicon.ico HTTP/1.1\" 404 209\n"
    },
    "wazuh": {
        "agent": {
            "id": "001",
            "name": "agentSim",
            "version": "PoC"
        },
        "event": {
            "format": "text",
            "id": "9aa69e7b-e1b0-530e-a710-49108e86019b",
            "ingested": "2021-10-26T16:50:34.348945Z",
            "kind": "event"
        },
        "host": {
            "architecture": "x86_64",
            "hostname": "hive",
            "ip": "127.0.1.1",
            "mac": "B0:7D:64:11:B3:13",
            "os": {
                "kernel": "5.14.14-arch1-1",
                "name": "Linux",
                "type": "posix",
                "version": "#1 SMP PREEMPT Wed, 20 Oct 2021 21:35:18 +0000"
            }
        },
        "module": {
            "name": "logcollector",
            "source": "apache-access"
        }
    }
})";

auto compact_message =
    R"({"event":{"original":"::1 - - [26/Dec/2016:16:16:29 +0200] \"GET /favicon.ico HTTP/1.1\" 404 209\n"},"wazuh":{"agent":{"id":"001","name":"agentSim","version":"PoC"},"event":{"format":"text","id":"9aa69e7b-e1b0-530e-a710-49108e86019b","ingested":"2021-10-26T16:50:34.348945Z","kind":"event"},"host":{"architecture":"x86_64","hostname":"hive","ip":"127.0.1.1","mac":"B0:7D:64:11:B3:13","os":{"kernel":"5.14.14-arch1-1","name":"Linux","type":"posix","version":"#1 SMP PREEMPT Wed, 20 Oct 2021 21:35:18 +0000"}},"module":{"name":"logcollector","source":"apache-access"}}}
)";

constexpr auto FILE_PATH = "/tmp/file";

class FileOutputTest : public ::testing::Test
{
    void SetUp() override
    {
        if (std::filesystem::exists(FILE_PATH))
        {
            std::filesystem::remove(FILE_PATH);
        }
    }

    void TearDown() override
    {
        if (std::filesystem::exists(FILE_PATH))
        {
            std::filesystem::remove(FILE_PATH);
        }
    }
};

using builder::builders::detail::FileOutput;

TEST_F(FileOutputTest, Create)
{
    ASSERT_NO_THROW(FileOutput(std::string {FILE_PATH}));
    ASSERT_TRUE(std::filesystem::exists(FILE_PATH));
}

TEST_F(FileOutputTest, UnknownPath)
{
    ASSERT_THROW(FileOutput("/tmp45/file"), std::invalid_argument);
}

TEST_F(FileOutputTest, Write)
{
    auto msg = std::make_shared<json::Json>(messageStr);
    auto output = FileOutput(FILE_PATH);
    ASSERT_NO_THROW(output.write(msg));

    std::ifstream ifs(FILE_PATH);
    std::stringstream buffer;
    buffer << ifs.rdbuf();

    ASSERT_EQ(buffer.str(), compact_message);
}
} // namespace fileoutputtest

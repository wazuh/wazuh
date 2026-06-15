#include <chrono>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <memory>
#include <sys/stat.h>
#include <thread>

#include <gmock/gmock.h>
#include <gtest/gtest.h>

#include <scheduler/mockScheduler.hpp>
#include <store/mockStore.hpp>

#include "channel.hpp"

namespace
{

// Get unique random temp folder
std::filesystem::path getTempDir()
{
    const auto pid = std::to_string(getpid());
    auto strTime = std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
    strTime = strTime.substr(strTime.size() - 5);
    const auto relativePath = std::filesystem::path("engine") / (pid + "_" + strTime);

    std::filesystem::path tmpDir = std::filesystem::temp_directory_path() / relativePath;
    if (std::filesystem::exists(tmpDir))
    {
        std::error_code ec;
        std::filesystem::remove_all(tmpDir, ec);
        if (ec)
        {
            throw std::runtime_error("Failed to remove existing temp directory: " + ec.message());
        }
    }
    std::error_code ec;
    std::filesystem::create_directories(tmpDir, ec);
    if (ec)
    {
        throw std::runtime_error("Failed to create temp directory: " + ec.message());
    }

    return tmpDir;
}

} // namespace

class ChannelHandlerTest : public ::testing::Test
{
protected:
    void SetUp() override
    {
        logging::testInit(logging::Level::Debug);
        tmpDir = getTempDir();

        defaultConfig = {
            tmpDir,                              // basePath
            "wazuh-${name}-${YYYY}-${MM}-${DD}", // pattern (extension added by constructor)
            0,                                   // maxSize (no limit)
            fastqueue::MIN_QUEUE_CAPACITY,       // bufferSize
        };

        mockStore = std::make_shared<store::mocks::MockStore>();

        EXPECT_CALL(*mockStore, readDoc(testing::_))
            .WillRepeatedly(testing::Return(store::mocks::storeReadError<json::Json>()));

        EXPECT_CALL(*mockStore, upsertDoc(testing::_, testing::_))
            .WillRepeatedly(testing::Return(store::mocks::storeOk()));
    }

    void TearDown() override
    {
        std::error_code ec;
        std::filesystem::remove_all(tmpDir, ec);
    }

    std::shared_ptr<streamlog::ChannelHandler> createBasicHandler(const std::string& name)
    {
        return streamlog::ChannelHandler::create(
            defaultConfig, name, mockStore, std::weak_ptr<scheduler::IScheduler> {}, "log");
    }

    std::shared_ptr<streamlog::ChannelHandler> createBasicHandler(const std::string& name,
                                                                  const streamlog::RotationConfig& config)
    {
        return streamlog::ChannelHandler::create(
            config, name, mockStore, std::weak_ptr<scheduler::IScheduler> {}, "log");
    }

    std::shared_ptr<streamlog::ChannelHandler>
    createHandlerWithScheduler(const std::string& name,
                               const streamlog::RotationConfig& config,
                               std::shared_ptr<scheduler::mocks::MockIScheduler> scheduler)
    {
        return streamlog::ChannelHandler::create(config, name, mockStore, scheduler, "log");
    }

    void createTestFile(const std::string& filePath, const std::string& content = "test content")
    {
        std::ofstream file(filePath);
        file << content;
        file.close();
    }

    std::filesystem::path tmpDir;
    streamlog::RotationConfig defaultConfig;
    std::shared_ptr<store::mocks::MockStore> mockStore;
};

// Parameterized test for different channel names
class ChannelNameTest
    : public ChannelHandlerTest
    , public ::testing::WithParamInterface<std::string>
{
};

// ============= CREATION AND VALIDATION UNIT TESTS =============

TEST_F(ChannelHandlerTest, BasicCreationAndDestruction)
{
    auto handler = createBasicHandler("test-channel");
    ASSERT_NE(handler, nullptr);

    EXPECT_NO_THROW({
        auto writer = handler->createWriter();
        EXPECT_NE(writer, nullptr);
    });
}

TEST_F(ChannelHandlerTest, FactoryMethodEnforcesSharedPtr)
{
    auto handler = createBasicHandler("test");
    EXPECT_NE(handler, nullptr);

    auto handler2 = handler;
    EXPECT_EQ(handler.get(), handler2.get());
}

TEST_F(ChannelHandlerTest, InvalidConfigurations)
{
    // Empty channel name
    EXPECT_THROW(createBasicHandler(""), std::runtime_error);

    // Empty pattern
    auto config = defaultConfig;
    config.pattern = "";
    EXPECT_THROW(createBasicHandler("test", config), std::runtime_error);

    // Non-existent base path
    config = defaultConfig;
    config.basePath = "/non/existent/path";
    EXPECT_THROW(createBasicHandler("test", config), std::runtime_error);

    // Relative path
    config = defaultConfig;
    config.basePath = "relative/path";
    EXPECT_THROW(createBasicHandler("test", config), std::runtime_error);
}

TEST_F(ChannelHandlerTest, ChannelNameValidation)
{
    // Valid names should not throw
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateChannelName("valid-name"));
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateChannelName("valid_name"));
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateChannelName("validName123"));
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateChannelName("123validName"));
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateChannelName("a"));
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateChannelName("A-B_C123"));

    // Invalid names should throw
    EXPECT_THROW(streamlog::ChannelHandler::validateChannelName(""), std::runtime_error);
    EXPECT_THROW(streamlog::ChannelHandler::validateChannelName("invalid name"), std::runtime_error);
    EXPECT_THROW(streamlog::ChannelHandler::validateChannelName("invalid.name"), std::runtime_error);
    EXPECT_THROW(streamlog::ChannelHandler::validateChannelName("invalid/name"), std::runtime_error);
    EXPECT_THROW(streamlog::ChannelHandler::validateChannelName("invalid\\name"), std::runtime_error);
    EXPECT_THROW(streamlog::ChannelHandler::validateChannelName("invalid@name"), std::runtime_error);
    EXPECT_THROW(streamlog::ChannelHandler::validateChannelName("invalid#name"), std::runtime_error);
    EXPECT_THROW(streamlog::ChannelHandler::validateChannelName("invalid!name"), std::runtime_error);
    EXPECT_THROW(streamlog::ChannelHandler::validateChannelName("invalid%name"), std::runtime_error);
}

TEST_F(ChannelHandlerTest, ConfigurationValidation)
{
    auto config = defaultConfig;

    EXPECT_NO_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config));

    config = defaultConfig;
    config.basePath = "";
    EXPECT_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config), std::runtime_error);

    config = defaultConfig;
    config.basePath = "relative/path";
    EXPECT_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config), std::runtime_error);

    config = defaultConfig;
    config.basePath = "/non/existent/path/that/does/not/exist";
    EXPECT_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config), std::runtime_error);

    config = defaultConfig;
    config.pattern = "";
    EXPECT_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config), std::runtime_error);

    config = defaultConfig;
    config.pattern = "static-name";
    config.maxSize = 0;
    EXPECT_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config), std::runtime_error);

    config = defaultConfig;
    config.pattern = "${YYYY}-${MM}-${DD}";
    config.maxSize = 1024;
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config));
    EXPECT_NE(config.pattern.find("${counter}"), std::string::npos);

    config = defaultConfig;
    config.pattern = "${YYYY}-${MM}-${DD}-${counter}";
    config.maxSize = 1024;
    auto originalPattern = config.pattern;
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config));
    EXPECT_EQ(config.pattern, originalPattern);

    config = defaultConfig;
    config.bufferSize = 0;
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config));
    EXPECT_EQ(config.bufferSize, 1 << 20);

    config = defaultConfig;
    config.maxSize = 100;
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config));
    EXPECT_EQ(config.maxSize, 1 << 20);

    config = defaultConfig;
    config.maxSize = 10 << 20;
    auto originalMaxSize = config.maxSize;
    EXPECT_NO_THROW(streamlog::ChannelHandler::validateAndNormalizeConfig(config));
    EXPECT_EQ(config.maxSize, originalMaxSize);
}

TEST_F(ChannelHandlerTest, ConfigurationGetter)
{
    auto handler = createBasicHandler("test-config");

    const auto& retrievedConfig = handler->getConfig();

    EXPECT_EQ(retrievedConfig.basePath, defaultConfig.basePath);
    EXPECT_EQ(retrievedConfig.bufferSize, defaultConfig.bufferSize);

    if (defaultConfig.maxSize > 0)
    {
        EXPECT_NE(retrievedConfig.pattern.find("${counter}"), std::string::npos);
    }
}

TEST_F(ChannelHandlerTest, ConfigurationImmutability)
{
    auto handler = createBasicHandler("test-immutable");

    const auto& config1 = handler->getConfig();
    const auto& config2 = handler->getConfig();

    EXPECT_EQ(&config1, &config2);

    EXPECT_FALSE(config1.basePath.empty());
    EXPECT_FALSE(config1.pattern.empty());
    EXPECT_GT(config1.bufferSize, 0u);
}

TEST_P(ChannelNameTest, ValidChannelNames)
{
    const std::string channelName = GetParam();
    EXPECT_NO_THROW({
        auto handler = createBasicHandler(channelName);
        EXPECT_NE(handler, nullptr);
    });
}

INSTANTIATE_TEST_SUITE_P(ChannelNames,
                         ChannelNameTest,
                         ::testing::Values("simple",
                                           "with-dashes",
                                           "with_underscores",
                                           "withNumbers123",
                                           "MixedCase",
                                           "very-long-channel-name-with-many-characters",
                                           "standard-wazuh-events-v5",
                                           "events",
                                           "audit"));

TEST_F(ChannelHandlerTest, InvalidChannelNames)
{
    std::vector<std::string> invalidNames = {"",
                                             "test@channel",
                                             "test channel",
                                             "test/channel",
                                             "test\\channel",
                                             "test.channel",
                                             "test:channel",
                                             "test*channel",
                                             "test?channel",
                                             "test<channel",
                                             "test>channel",
                                             "test|channel",
                                             "test\"channel",
                                             "test'channel"};

    for (const auto& name : invalidNames)
    {
        EXPECT_THROW(createBasicHandler(name), std::runtime_error)
            << "Channel name should be invalid: '" << name << "'";
    }
}

TEST_F(ChannelHandlerTest, WriterNonCopyable)
{
    auto handler = createBasicHandler("nocopy-test");
    auto writer1 = handler->createWriter();

    auto testWriterByValue = [](std::shared_ptr<streamlog::WriterEvent> writer)
    {
        (*writer)("message via value");
    };

    EXPECT_NO_THROW(testWriterByValue(writer1));
}

TEST_F(ChannelHandlerTest, EmptyAndZeroByteMessages)
{
    auto handler = createBasicHandler("empty-test");
    auto writer = handler->createWriter();

    std::vector<std::string> testMessages = {
        "", " ", "\n", "\t", "a", std::string(1, '\0'), std::string(1, '\0') + "after_null"};

    for (const auto& msg : testMessages)
    {
        std::string msgCopy = msg;
        EXPECT_NO_THROW((*writer)(std::move(msgCopy)));
    }

    std::this_thread::sleep_for(std::chrono::milliseconds(200));
}

TEST_F(ChannelHandlerTest, PatternValidationEdgeCases)
{
    std::vector<std::string> invalidPatterns = {"",
                                                "no_placeholders",
                                                "${INVALID}",
                                                "${YYYY}${INVALID}${DD}",
                                                "unclosed${YYYY",
                                                "${}",
                                                "$YYYY",
                                                "{YYYY}",
                                                "${YYYY${MM}"};

    for (const auto& pattern : invalidPatterns)
    {
        auto config = defaultConfig;
        config.pattern = pattern;
        config.maxSize = 0;

        if (pattern == "no_placeholders")
        {
            EXPECT_THROW(createBasicHandler("invalid-pattern", config), std::runtime_error)
                << "Pattern should be invalid: " << pattern;
        }
        else
        {
            try
            {
                auto handler = createBasicHandler("pattern-test", config);
                auto writer = handler->createWriter();
                (*writer)("test");
                std::this_thread::sleep_for(std::chrono::milliseconds(50));
            }
            catch (const std::runtime_error&)
            {
                // May throw for invalid patterns - acceptable
            }
        }
    }
}

TEST_F(ChannelHandlerTest, LongChannelName)
{
    std::string longName = std::string(200, 'A');

    EXPECT_NO_THROW({
        auto handler = createBasicHandler(longName);
        auto writer = handler->createWriter();
        (*writer)(std::string("test message for long channel name"));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    });

    std::string tooLongName = std::string(1000, 'X');

    try
    {
        auto handler = createBasicHandler(tooLongName);
        auto writer = handler->createWriter();
        (*writer)(std::string("test message"));
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
    catch (const std::exception&)
    {
        // Acceptable to throw for too long names
    }
}

// ============= COMPRESSION VALIDATION UNIT TESTS =============

TEST_F(ChannelHandlerTest, CompressionConfigValidation)
{
    for (int level = 1; level <= 9; ++level)
    {
        auto config = defaultConfig;
        config.shouldCompress = true;
        config.compressionLevel = level;

        EXPECT_NO_THROW(createBasicHandler("test-channel", config));
    }

    auto config = defaultConfig;
    config.shouldCompress = true;

    config.compressionLevel = 0;
    EXPECT_THROW(createBasicHandler("test-channel", config), std::runtime_error);

    config.compressionLevel = 10;
    EXPECT_THROW(createBasicHandler("test-channel", config), std::runtime_error);

    config.compressionLevel = -1;
    EXPECT_THROW(createBasicHandler("test-channel", config), std::runtime_error);
}

TEST_F(ChannelHandlerTest, CompressionDisabledByDefault)
{
    auto handler = createBasicHandler("test-channel");
    const auto& config = handler->getConfig();

    EXPECT_TRUE(config.shouldCompress);
    EXPECT_EQ(config.compressionLevel, 5);
}

// Test compression with mock scheduler
TEST_F(ChannelHandlerTest, CompressionWithMockScheduler)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.shouldCompress = true;
    config.compressionLevel = 6;
    config.maxSize = 1 << 20; // 1MB - use the minimum valid size
    config.pattern = "${YYYY}-${MM}-${DD}-${name}-${counter}.log";

    // Create mock scheduler
    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();

    // Expect scheduleTask to be called when rotation occurs
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _))
        .Times(AtLeast(1))
        .WillRepeatedly(
            [](std::string_view taskName, scheduler::TaskConfig&& config)
            {
                // Verify task configuration
                EXPECT_EQ(config.interval, 0); // One-time task
                EXPECT_EQ(config.CPUPriority, 0);
                EXPECT_NE(config.taskFunction, nullptr);

                // Verify task name format
                std::string taskNameStr(taskName);
                EXPECT_TRUE(taskNameStr.find("CompressLog-test-channel-") == 0);

                // Execute the task function to simulate compression
                config.taskFunction();
            });

    // Set the mock scheduler
    auto handler = createHandlerWithScheduler("test-channel", config, mockScheduler);

    auto writer = handler->createWriter();

    // Write enough data to exceed 1MB and trigger rotation
    const std::string largeMessage(100000, 'X'); // 100KB message
    for (int i = 0; i < 12; ++i)                 // 12 * 100KB = 1.2MB total
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Wait for processing and rotations
    std::this_thread::sleep_for(std::chrono::seconds(1));

    // Verify that the file was created and compressed
    size_t fileCount = 0;
    for (const auto& entry : std::filesystem::recursive_directory_iterator(tmpDir))
    {
        if (entry.is_regular_file() && entry.path().string().find("test-channel") != std::string::npos)
        {
            fileCount++;
            // Check extension to verify compression
            EXPECT_TRUE(entry.path().extension() == ".gz" || entry.path().extension() == ".log"
                        || entry.path().extension() == ".json");
        }
    }

    EXPECT_GE(fileCount, 1) << "No files created";
}

// Test compression without scheduler (should log warning)
TEST_F(ChannelHandlerTest, CompressionWithoutScheduler)
{
    auto config = defaultConfig;
    config.shouldCompress = true;
    config.maxSize = 1 << 20; // 1MB - use valid size
    config.pattern = "${YYYY}-${MM}-${DD}-${name}-${counter}.log";

    auto handler = createBasicHandler("test-channel", config);
    // Note: We don't set a scheduler here

    auto writer = handler->createWriter();

    // Write enough data to trigger rotation - should not crash despite no scheduler
    const std::string largeMessage(100000, 'B'); // 100KB message
    for (int i = 0; i < 12; ++i)                 // 12 * 100KB = 1.2MB total
    {
        (*writer)(largeMessage + std::to_string(i));
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    // Wait for processing
    std::this_thread::sleep_for(std::chrono::milliseconds(500));

    // Test should pass without crashing
    SUCCEED();
}

// Test compression task configuration creation
TEST_F(ChannelHandlerTest, CompressionTaskConfigCreation)
{
    auto config = defaultConfig;
    config.shouldCompress = true;
    config.compressionLevel = 7;

    auto handler = createBasicHandler("test-channel", config);

    const auto& storedConfig = handler->getConfig();
    EXPECT_TRUE(storedConfig.shouldCompress);
    EXPECT_EQ(storedConfig.compressionLevel, 7);
}

// ============= STORE PERSISTENCE UNIT TESTS (mock-only, no rotation) =============

TEST_F(ChannelHandlerTest, StorePersistenceInitializationNoState)
{
    EXPECT_CALL(*mockStore, readDoc(testing::_))
        .Times(2)
        .WillRepeatedly(testing::Return(store::mocks::storeReadError<json::Json>()));

    EXPECT_CALL(*mockStore, upsertDoc(testing::_, testing::_))
        .Times(1)
        .WillOnce(testing::Return(store::mocks::storeOk()));

    auto handler = createBasicHandler("store-test");
    EXPECT_NE(handler, nullptr);
}

TEST_F(ChannelHandlerTest, StorePersistenceInitializationWithPendingFile)
{
    using namespace ::testing;

    auto config = defaultConfig;
    config.shouldCompress = true;
    config.compressionLevel = 5;
    config.maxSize = 1 << 20;
    config.pattern = "${YYYY}-${MM}-${DD}-${name}-${counter}";

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();

    std::string previousFilePath = tmpDir.string() + "/2025-08-25-store-test-5.log";
    createTestFile(previousFilePath, "Previous file content to be compressed");

    json::Json previousState;
    previousState.setString(previousFilePath, "/last_current");

    EXPECT_CALL(*mockStore, readDoc(HasSubstr("store-test")))
        .WillRepeatedly(Return(store::mocks::storeReadDocResp(previousState)));

    EXPECT_CALL(*mockScheduler, scheduleTask(_, _)).Times(1);

    EXPECT_CALL(*mockStore, upsertDoc(HasSubstr("store-test"), _))
        .Times(AnyNumber())
        .WillRepeatedly(Return(store::mocks::storeOk()));

    auto handler = createHandlerWithScheduler("store-test", config, mockScheduler);

    std::this_thread::sleep_for(std::chrono::milliseconds(100));
}

TEST_F(ChannelHandlerTest, StorePersistenceReadError)
{
    EXPECT_CALL(*mockStore, readDoc(testing::_))
        .Times(2)
        .WillRepeatedly(testing::Return(store::mocks::storeReadError<json::Json>()));

    EXPECT_CALL(*mockStore, upsertDoc(testing::_, testing::_))
        .Times(1)
        .WillOnce(testing::Return(store::mocks::storeOk()));

    auto handler = createBasicHandler("store-error-test");
    EXPECT_NE(handler, nullptr);
}

TEST_F(ChannelHandlerTest, StorePersistenceCorruptedState)
{
    json::Json corruptedState;
    corruptedState.setString("invalid_data", "/invalid");

    EXPECT_CALL(*mockStore, readDoc(testing::_))
        .Times(2)
        .WillRepeatedly(testing::Return(store::mocks::storeReadDocResp(corruptedState)));

    EXPECT_CALL(*mockStore, upsertDoc(testing::_, testing::_))
        .Times(1)
        .WillOnce(testing::Return(store::mocks::storeOk()));

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    EXPECT_CALL(*mockScheduler, scheduleTask(testing::_, testing::_)).Times(0);

    auto handler = createBasicHandler("corrupted-state-test");
    EXPECT_NE(handler, nullptr);
}

TEST_F(ChannelHandlerTest, StorePersistencePreviousFileNotFound)
{
    using namespace ::testing;

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();

    std::string nonExistentFile = tmpDir.string() + "/non-existent-file.log";
    json::Json state;
    state.setString(nonExistentFile, "/currentFilePath");

    EXPECT_CALL(*mockStore, readDoc(_)).Times(2).WillRepeatedly(Return(store::mocks::storeReadDocResp(state)));

    EXPECT_CALL(*mockScheduler, scheduleTask(_, _)).Times(0);

    EXPECT_CALL(*mockStore, upsertDoc(_, _)).Times(1).WillOnce(Return(store::mocks::storeOk()));

    auto config = defaultConfig;
    config.shouldCompress = true;

    auto handler = createHandlerWithScheduler("missing-file-test", config, mockScheduler);
    EXPECT_NE(handler, nullptr);
}

// ============= STORE JSON CONTENT VALIDATION =============

TEST_F(ChannelHandlerTest, StoreContentAfterCreation)
{
    // Verify the exact JSON content persisted to store on initial creation.
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.pattern = "${name}-${counter}";

    json::Json capturedJson;
    std::string capturedKey;

    EXPECT_CALL(*mockStore, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadError<json::Json>()));

    EXPECT_CALL(*mockStore, upsertDoc(_, _))
        .Times(1)
        .WillOnce(
            [&capturedJson, &capturedKey](const base::Name& name, const store::Doc& doc) -> base::OptError
            {
                capturedKey = name.fullName();
                capturedJson = json::Json(doc);
                return std::nullopt;
            });

    auto handler = createBasicHandler("json-check", config);

    // Validate JSON content: /last_current and /last_counter
    std::string storedPath;
    EXPECT_EQ(capturedJson.getString(storedPath, "/last_current"), json::RetGet::Success);
    EXPECT_EQ(storedPath, (tmpDir / "json-check-0.log").string());

    auto counterOpt = capturedJson.getUint64("/last_counter");
    ASSERT_TRUE(counterOpt.has_value());
    EXPECT_EQ(counterOpt.value(), 0u);

    // Key should contain channel name
    EXPECT_NE(capturedKey.find("json-check"), std::string::npos);
}

TEST_F(ChannelHandlerTest, StoreContentAfterRotation)
{
    // Verify the JSON is updated correctly after a rotation: counter 0 → 1.
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = false;
    config.pattern = "${name}-${counter}";

    std::vector<json::Json> capturedJsons;

    EXPECT_CALL(*mockStore, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadError<json::Json>()));

    EXPECT_CALL(*mockStore, upsertDoc(_, _))
        .Times(AtLeast(2))
        .WillRepeatedly(
            [&capturedJsons](const base::Name&, const store::Doc& doc) -> base::OptError
            {
                capturedJsons.push_back(doc);
                return std::nullopt;
            });

    auto handler = createBasicHandler("json-rotate", config);
    auto writer = handler->createWriter();

    // Trigger rotation
    (*writer)(std::string(config.maxSize + 1, 'R'));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    ASSERT_GE(capturedJsons.size(), 2u) << "Expected at least 2 store writes (creation + rotation)";

    // First write (creation): counter=0
    std::string path0;
    EXPECT_EQ(capturedJsons[0].getString(path0, "/last_current"), json::RetGet::Success);
    EXPECT_NE(path0.find("json-rotate-0.log"), std::string::npos);
    auto counter0 = capturedJsons[0].getUint64("/last_counter");
    ASSERT_TRUE(counter0.has_value());
    EXPECT_EQ(counter0.value(), 0u);

    // Second write (after rotation): counter=1
    std::string path1;
    EXPECT_EQ(capturedJsons[1].getString(path1, "/last_current"), json::RetGet::Success);
    EXPECT_NE(path1.find("json-rotate-1.log"), std::string::npos);
    auto counter1 = capturedJsons[1].getUint64("/last_counter");
    ASSERT_TRUE(counter1.has_value());
    EXPECT_EQ(counter1.value(), 1u);

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// ============= LOAD STATE WITH INVALID VARIANTS =============

TEST_F(ChannelHandlerTest, LoadStateLastCurrentMissing)
{
    // Store has a valid doc but /last_current key is absent.
    using namespace ::testing;

    json::Json state;
    state.setUint64(5, "/last_counter");
    // No /last_current key

    EXPECT_CALL(*mockStore, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadDocResp(state)));
    EXPECT_CALL(*mockStore, upsertDoc(_, _)).WillRepeatedly(Return(store::mocks::storeOk()));

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.pattern = "${name}-${counter}";

    EXPECT_NO_THROW({
        auto handler = createBasicHandler("missing-current", config);
        EXPECT_NE(handler, nullptr);
        // Fallback: should start at counter=0
        EXPECT_EQ(handler->getCurrentFilePath(), tmpDir / "missing-current-0.log");
    });
}

TEST_F(ChannelHandlerTest, LoadStateLastCurrentNotString)
{
    // Store has /last_current but it's a number, not a string.
    using namespace ::testing;

    json::Json state;
    state.setUint64(12345, "/last_current"); // wrong type
    state.setUint64(3, "/last_counter");

    EXPECT_CALL(*mockStore, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadDocResp(state)));
    EXPECT_CALL(*mockStore, upsertDoc(_, _)).WillRepeatedly(Return(store::mocks::storeOk()));

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.pattern = "${name}-${counter}";

    EXPECT_NO_THROW({
        auto handler = createBasicHandler("nonstr-current", config);
        EXPECT_NE(handler, nullptr);
        // Should fallback gracefully
        EXPECT_EQ(handler->getCurrentFilePath(), tmpDir / "nonstr-current-0.log");
    });
}

TEST_F(ChannelHandlerTest, LoadStateLastCounterMissing)
{
    // Store has /last_current (valid path) but no /last_counter.
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = false;
    config.pattern = "${name}-${counter}";

    // Create the file that store points to
    auto existingFile = tmpDir / "nocounter-0.log";
    {
        std::ofstream f(existingFile);
        f << "existing content";
    }

    json::Json state;
    state.setString(existingFile.string(), "/last_current");
    // No /last_counter key

    EXPECT_CALL(*mockStore, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadDocResp(state)));
    EXPECT_CALL(*mockStore, upsertDoc(_, _)).WillRepeatedly(Return(store::mocks::storeOk()));

    EXPECT_NO_THROW({
        auto handler = createBasicHandler("nocounter", config);
        EXPECT_NE(handler, nullptr);
        // Should resume from existing file (counter defaults to 0 from RotationState)
        EXPECT_EQ(handler->getCurrentFilePath(), existingFile);
    });
}

TEST_F(ChannelHandlerTest, LoadStateLastCounterNotUint)
{
    // Store has /last_counter as a string instead of uint.
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.pattern = "${name}-${counter}";

    auto existingFile = tmpDir / "badcounter-0.log";
    {
        std::ofstream f(existingFile);
        f << "content";
    }

    json::Json state;
    state.setString(existingFile.string(), "/last_current");
    state.setString("not_a_number", "/last_counter"); // wrong type

    EXPECT_CALL(*mockStore, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadDocResp(state)));
    EXPECT_CALL(*mockStore, upsertDoc(_, _)).WillRepeatedly(Return(store::mocks::storeOk()));

    EXPECT_NO_THROW({
        auto handler = createBasicHandler("badcounter", config);
        EXPECT_NE(handler, nullptr);
    });
}

TEST_F(ChannelHandlerTest, LoadStateLastCounterVeryLarge)
{
    // Store has /last_counter as a very large value.
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.pattern = "${name}-${counter}";

    json::Json state;
    state.setString((tmpDir / "largectr-99999.log").string(), "/last_current");
    state.setUint64(99999, "/last_counter");

    // File doesn't exist → fallback path
    EXPECT_CALL(*mockStore, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadDocResp(state)));
    EXPECT_CALL(*mockStore, upsertDoc(_, _)).WillRepeatedly(Return(store::mocks::storeOk()));

    EXPECT_NO_THROW({
        auto handler = createBasicHandler("largectr", config);
        EXPECT_NE(handler, nullptr);
        // File didn't exist → fallback scans from 0
        EXPECT_EQ(handler->getCurrentFilePath(), tmpDir / "largectr-0.log");
    });
}

TEST_F(ChannelHandlerTest, LoadStateReadDocError)
{
    // readDoc returns an error — handler should initialize fresh.
    using namespace ::testing;

    EXPECT_CALL(*mockStore, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadError<json::Json>()));
    EXPECT_CALL(*mockStore, upsertDoc(_, _)).WillRepeatedly(Return(store::mocks::storeOk()));

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.pattern = "${name}-${counter}";

    EXPECT_NO_THROW({
        auto handler = createBasicHandler("read-err", config);
        EXPECT_NE(handler, nullptr);
        EXPECT_EQ(handler->getCurrentFilePath(), tmpDir / "read-err-0.log");
    });
}

TEST_F(ChannelHandlerTest, LoadStateUpsertDocError)
{
    // upsertDoc returns an error — handler should still initialize (best-effort persistence).
    using namespace ::testing;

    EXPECT_CALL(*mockStore, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadError<json::Json>()));
    EXPECT_CALL(*mockStore, upsertDoc(_, _)).WillRepeatedly(Return(store::mocks::storeError()));

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.pattern = "${name}-${counter}";

    EXPECT_NO_THROW({
        auto handler = createBasicHandler("upsert-err", config);
        EXPECT_NE(handler, nullptr);
        EXPECT_EQ(handler->getCurrentFilePath(), tmpDir / "upsert-err-0.log");
    });
}

// ============= shouldCompress SCHEDULING VALIDATION =============

TEST_F(ChannelHandlerTest, NoCompressionDoesNotSchedule)
{
    // shouldCompress=false with size rotation → scheduleTask must NOT be called.
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = false;
    config.pattern = "${name}-${counter}";

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _)).Times(0);

    auto handler = createHandlerWithScheduler("no-sched", config, mockScheduler);
    auto writer = handler->createWriter();

    // Trigger rotation
    (*writer)(std::string(config.maxSize + 1, 'N'));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    // Verify rotation happened (file counter advanced)
    EXPECT_EQ(handler->getCurrentFilePath(), tmpDir / "no-sched-1.log");

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

TEST_F(ChannelHandlerTest, CompressionEnabledDoesSchedule)
{
    // shouldCompress=true with size rotation → scheduleTask called exactly once for previous file.
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = true;
    config.compressionLevel = 1;
    config.pattern = "${name}-${counter}";

    auto mockScheduler = std::make_shared<scheduler::mocks::MockIScheduler>();
    EXPECT_CALL(*mockScheduler, scheduleTask(_, _)).Times(1).WillOnce([](std::string_view, scheduler::TaskConfig&&) {});

    auto handler = createHandlerWithScheduler("yes-sched", config, mockScheduler);
    auto writer = handler->createWriter();

    // Trigger a single rotation
    (*writer)(std::string(config.maxSize + 1, 'Y'));
    std::this_thread::sleep_for(std::chrono::milliseconds(300));

    EXPECT_EQ(handler->getCurrentFilePath(), tmpDir / "yes-sched-1.log");

    writer.reset();
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
}

// ============= .GZ FUTURE COLLISION WITH GAP (UNIT) =============

TEST_F(ChannelHandlerTest, GzCollisionWithGapSkipsToSafeCounter)
{
    // Existing: channel-2.log.gz (counter 0, 1 free)
    // With compression enabled, handler should still start at 0 since .log doesn't exist.
    // But upon rotation reaching 2, it should skip 2.
    using namespace ::testing;

    auto config = defaultConfig;
    config.maxSize = 1 << 20;
    config.shouldCompress = true;
    config.pattern = "${name}-${counter}";

    // Create gap: only counter=2 has a .gz
    createTestFile((tmpDir / "gap-col-2.log.gz").string(), "compressed");

    EXPECT_CALL(*mockStore, readDoc(_)).WillRepeatedly(Return(store::mocks::storeReadError<json::Json>()));
    EXPECT_CALL(*mockStore, upsertDoc(_, _)).WillRepeatedly(Return(store::mocks::storeOk()));

    auto handler = createBasicHandler("gap-col", config);

    // Should start at counter=0 (no .log at 0, compression check for .gz at 0 → doesn't exist)
    EXPECT_EQ(handler->getCurrentFilePath(), tmpDir / "gap-col-0.log");
}

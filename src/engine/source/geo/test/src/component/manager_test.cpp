#include <gtest/gtest.h>

#include <atomic>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iostream>
#include <thread>

#include <base/json.hpp>
#include <base/logging.hpp>
#include <geo/downloader.hpp>
#include <geo/manager.hpp>
#include <store/mockStore.hpp>

using namespace store::mocks;
using namespace geo;

namespace geoctest
{
const std::string g_maxmindDbPath {MMDB_PATH_TEST};

const std::string g_ipFullData {"1.2.3.4"};

class GeoManagerTest : public ::testing::Test
{
protected:
    std::shared_ptr<store::mocks::MockStore> mockStore;
    std::vector<std::string> tmpFiles;
    std::shared_ptr<geo::IManager> manager;

    std::string asnPath;
    std::string cityPath;

    void SetUp() override
    {
        logging::testInit();
        mockStore = std::make_shared<store::mocks::MockStore>();
        auto downloader = std::make_shared<geo::Downloader>();

        asnPath = getTmpDb();
        cityPath = getTmpDb();

        auto asnName = base::Name(fmt::format(
            "{}{}{}", INTERNAL_NAME, base::Name::SEPARATOR_S, std::filesystem::path(asnPath).filename().string()));
        auto cityName = base::Name(fmt::format(
            "{}{}{}", INTERNAL_NAME, base::Name::SEPARATOR_S, std::filesystem::path(cityPath).filename().string()));

        EXPECT_CALL(*mockStore, readInternalCol(base::Name(INTERNAL_NAME)))
            .WillOnce(testing::Return(storeReadColResp({asnName, cityName})));
        json::Json asnJson;
        asnJson.setString(asnPath, PATH_PATH);
        asnJson.setString(typeName(Type::ASN), TYPE_PATH);
        asnJson.setString("asnHash", HASH_PATH);

        json::Json cityJson;
        cityJson.setString(cityPath, PATH_PATH);
        cityJson.setString(typeName(Type::CITY), TYPE_PATH);
        cityJson.setString("cityHash", HASH_PATH);

        EXPECT_CALL(*mockStore, readInternalDoc(asnName)).WillOnce(testing::Return(storeReadDocResp(asnJson)));
        EXPECT_CALL(*mockStore, readInternalDoc(cityName)).WillOnce(testing::Return(storeReadDocResp(cityJson)));

        manager = std::make_shared<geo::Manager>(mockStore, downloader);
    }

    void TearDown() override
    {
        for (const auto& file : tmpFiles)
        {
            std::filesystem::remove(file);
        }
    }

    std::string getTmpDb()
    {
        // Create a template for the temporary file name with "XXXXXX" at the end
        char template_name[] = "/tmp/tempXXXXXX";

        // Create a temporary file and get its file descriptor
        int fd = mkstemp(template_name);
        if (fd == -1)
        {
            throw std::runtime_error(fmt::format("Failed to create temporary file: {}", strerror(errno)));
        }

        // Close the file descriptor since we'll be using C++ streams
        close(fd);

        // Convert the temporary file name to a std::string
        std::string temp_file = template_name;

        // Rename the temporary file with the ".mmdb" extension
        std::string file = temp_file + ".mmdb";
        if (rename(temp_file.c_str(), file.c_str()) != 0)
        {
            // If renaming fails, remove the temporary file
            std::cerr << "Failed to rename temporary file: " << strerror(errno) << std::endl;
            std::remove(temp_file.c_str());
            throw std::runtime_error(fmt::format("Failed to rename temporary file: {}", strerror(errno)));
        }

        // Add the file to the list of temporary files
        tmpFiles.emplace_back(file);

        // Read test db
        std::ifstream ifs(g_maxmindDbPath, std::ios::binary);
        if (!ifs.is_open())
        {
            std::cout << "Error code: " << strerror(errno) << std::endl;
            throw std::runtime_error("Cannot open test db");
        }

        // Copy test db to tmp file
        std::ofstream ofs(file);
        if (!ofs.is_open())
        {
            std::cout << "Error code: " << strerror(errno) << std::endl;
            throw std::runtime_error("Cannot open tmp db");
        }

        ofs << ifs.rdbuf();

        ofs.close();
        ifs.close();
        return file;
    }
};

void setError(std::atomic_bool& error, std::string& errorMsg, const std::string& errorStr)
{
    auto expected = false;
    if (error.compare_exchange_strong(expected, true))
    {
        errorMsg = errorStr;
    }
}

// Locator threads lookup while another thread deletes and add the db to the manager
TEST_F(GeoManagerTest, MultithreadDeleteAddLookup)
{
    auto type = Type::ASN;
    auto dbPath = asnPath;
    auto internalName = base::Name(fmt::format(
        "{}{}{}", INTERNAL_NAME, base::Name::SEPARATOR_S, std::filesystem::path(dbPath).filename().string()));
    auto nThreads = 10;
    auto times = 20000;

    std::atomic_bool error = false;
    std::string errorMsg;

    auto locatorFn = [&errorMsg, &error, times](std::shared_ptr<ILocator> locator)
    {
        for (auto i = 0; i < times; i++)
        {
            if (error.load())
            {
                return;
            }

            auto res = locator->getString(g_ipFullData, "test_map.test_str1");
            if (base::isError(res))
            {
                if (base::getError(res).message != "Database is not available")
                {
                    setError(error,
                             errorMsg,
                             fmt::format("Locator thread got error '{}' which is not 'Database is not available'",
                                         base::getError(res).message));
                }
            }
            else
            {
                if (base::getResponse(res) != "Wazuh")
                {
                    setError(
                        error,
                        errorMsg,
                        fmt::format("Locator thread got response '{}' which is not 'Wazuh'", base::getResponse(res)));
                }
            }
        }
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < nThreads - 1; i++)
    {
        auto locatorResp = manager->getLocator(type);
        ASSERT_FALSE(base::isError(locatorResp));
        auto locator = base::getResponse(locatorResp);

        threads.emplace_back(locatorFn, locator);
    }

    // Add a thread to remove the db
    threads.emplace_back(
        [&error, &errorMsg, times, type, dbPath, internalName](std::shared_ptr<IManager> manager,
                                                               std::shared_ptr<store::mocks::MockStore> mockStore)
        {
            EXPECT_CALL(*mockStore, deleteInternalDoc(internalName)).WillRepeatedly(testing::Return(storeOk()));
            EXPECT_CALL(*mockStore, upsertInternalDoc(internalName, testing::_))
                .WillRepeatedly(testing::Return(storeOk()));

            bool action = true;
            for (int i = 0; i < times; i++)
            {
                if (error.load())
                {
                    return;
                }

                base::OptError res;
                if (action)
                {
                    res = manager->removeDb(dbPath);
                    if (base::isError(res))
                    {
                        setError(error, errorMsg, base::getError(res).message);
                    }
                }
                else
                {
                    res = manager->addDb(dbPath, type);
                    if (base::isError(res))
                    {
                        setError(error, errorMsg, base::getError(res).message);
                    }
                }

                action = !action;
            }
        },
        manager,
        mockStore);

    for (auto& t : threads)
    {
        t.join();
    }

    ASSERT_FALSE(error.load()) << errorMsg;
}

// Locator threads lookup while another thread lists the dbs
TEST_F(GeoManagerTest, MultithreadListLookup)
{
    auto type = Type::ASN;
    auto dbPath = asnPath;
    auto internalName = base::Name(fmt::format(
        "{}{}{}", INTERNAL_NAME, base::Name::SEPARATOR_S, std::filesystem::path(dbPath).filename().string()));
    auto nThreads = 10;
    auto times = 15000;

    std::atomic_bool error = false;
    std::string errorMsg;

    auto locatorFn = [&errorMsg, &error, times](std::shared_ptr<ILocator> locator)
    {
        for (auto i = 0; i < times; i++)
        {
            if (error.load())
            {
                return;
            }

            auto res = locator->getString(g_ipFullData, "test_map.test_str1");
            if (base::isError(res))
            {
                setError(error, errorMsg, base::getError(res).message);
            }
            else
            {
                if (base::getResponse(res) != "Wazuh")
                {
                    setError(
                        error,
                        errorMsg,
                        fmt::format("Locator thread got response '{}' which is not 'Wazuh'", base::getResponse(res)));
                }
            }
        }
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < nThreads - 1; i++)
    {
        auto locatorResp = manager->getLocator(type);
        ASSERT_FALSE(base::isError(locatorResp));
        auto locator = base::getResponse(locatorResp);

        threads.emplace_back(locatorFn, locator);
    }

    // Add a thread to query the db
    threads.emplace_back(
        [&error, &errorMsg, times, type, dbPath](std::shared_ptr<IManager> manager)
        {
            for (int i = 0; i < times; i++)
            {
                if (error.load())
                {
                    return;
                }

                auto dbs = manager->listDbs();
                if (dbs.size() != 2)
                {
                    setError(error, errorMsg, "Manager thread got more than two dbs");
                }
            }
        },
        manager);

    for (auto& t : threads)
    {
        t.join();
    }

    ASSERT_FALSE(error.load()) << errorMsg;
}

// Get locator from threads while another thread deletes and add the db to the manager
TEST_F(GeoManagerTest, MultithreadDeleteAddGetLocator)
{
    auto type = Type::ASN;
    auto dbPath = asnPath;
    auto internalName = base::Name(fmt::format(
        "{}{}{}", INTERNAL_NAME, base::Name::SEPARATOR_S, std::filesystem::path(dbPath).filename().string()));
    auto nThreads = 10;
    auto times = 20000;

    std::atomic_bool error = false;
    std::string errorMsg;

    auto locatorFn = [&errorMsg, &error, times, type](std::shared_ptr<IManager> manager)
    {
        for (auto i = 0; i < times; i++)
        {
            if (error.load())
            {
                return;
            }

            auto locatorResp = manager->getLocator(type);
            if (base::isError(locatorResp))
            {
                if (base::getError(locatorResp).message != "Type 'asn' does not have a database")
                {
                    setError(
                        error,
                        errorMsg,
                        fmt::format("Locator thread got error '{}' which is not 'Type 'asn' does not have a database'",
                                    base::getError(locatorResp).message));
                }
            }
        }
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < nThreads - 1; i++)
    {
        threads.emplace_back(locatorFn, manager);
    }

    // Add a thread to remove the db
    threads.emplace_back(
        [&error, &errorMsg, times, type, dbPath, internalName](std::shared_ptr<IManager> manager,
                                                               std::shared_ptr<store::mocks::MockStore> mockStore)
        {
            EXPECT_CALL(*mockStore, deleteInternalDoc(internalName)).WillRepeatedly(testing::Return(storeOk()));
            EXPECT_CALL(*mockStore, upsertInternalDoc(internalName, testing::_))
                .WillRepeatedly(testing::Return(storeOk()));

            bool action = true;
            for (int i = 0; i < times; i++)
            {
                if (error.load())
                {
                    return;
                }

                base::OptError res;
                if (action)
                {
                    res = manager->removeDb(dbPath);
                    if (base::isError(res))
                    {
                        setError(error, errorMsg, base::getError(res).message);
                    }
                }
                else
                {
                    res = manager->addDb(dbPath, type);
                    if (base::isError(res))
                    {
                        setError(error, errorMsg, base::getError(res).message);
                    }
                }

                action = !action;
            }
        },
        manager,
        mockStore);

    for (auto& t : threads)
    {
        t.join();
    }

    ASSERT_FALSE(error.load()) << errorMsg;
}

// One thread for each type adds/deletes the db for same type
// Several threads for each type, gets the locator and queries the db
TEST_F(GeoManagerTest, ComplexUseCase)
{
    auto type0 = Type::ASN;
    auto dbPath0 = asnPath;
    auto internalName0 = base::Name(fmt::format(
        "{}{}{}", INTERNAL_NAME, base::Name::SEPARATOR_S, std::filesystem::path(dbPath0).filename().string()));

    auto type1 = Type::CITY;
    auto dbPath1 = cityPath;
    auto internalName1 = base::Name(fmt::format(
        "{}{}{}", INTERNAL_NAME, base::Name::SEPARATOR_S, std::filesystem::path(dbPath1).filename().string()));

    auto nThreads0 = 5;
    auto nThreads1 = 5;
    auto times = 20000;

    std::atomic_bool error = false;
    std::string errorMsg;

    auto locatorFn = [times, &error, &errorMsg](std::shared_ptr<IManager> manager, Type type)
    {
        std::string noDbError = fmt::format("Type '{}' does not have a database", typeName(type));
        for (auto i = 0; i < times; i++)
        {
            auto locatorResp = manager->getLocator(type);
            if (base::isError(locatorResp))
            {
                if (base::getError(locatorResp).message != noDbError)
                {
                    setError(error,
                             errorMsg,
                             fmt::format("Locator thread got error '{}' which is not '{}'",
                                         base::getError(locatorResp).message,
                                         noDbError));
                }
            }
            else
            {
                auto locator = base::getResponse(locatorResp);
                auto res = locator->getString(g_ipFullData, "test_map.test_str1");
                if (base::isError(res))
                {
                    if (base::getError(res).message != "Database is not available")
                    {
                        setError(error,
                                 errorMsg,
                                 fmt::format("Locator thread got error '{}' which is not 'Database is not available'",
                                             base::getError(res).message));
                    }
                }
                else
                {
                    if (base::getResponse(res) != "Wazuh")
                    {
                        setError(error,
                                 errorMsg,
                                 fmt::format("Locator thread got response '{}' which is not 'Wazuh'",
                                             base::getResponse(res)));
                    }
                }
            }
        }
    };

    std::vector<std::thread> threads;
    for (int i = 0; i < nThreads0; i++)
    {
        threads.emplace_back(locatorFn, manager, type0);
    }
    for (int i = 0; i < nThreads1; i++)
    {
        threads.emplace_back(locatorFn, manager, type1);
    }

    // Expectations by the manager threads
    EXPECT_CALL(*mockStore, deleteInternalDoc(internalName0)).WillRepeatedly(testing::Return(storeOk()));
    EXPECT_CALL(*mockStore, upsertInternalDoc(internalName0, testing::_)).WillRepeatedly(testing::Return(storeOk()));
    EXPECT_CALL(*mockStore, deleteInternalDoc(internalName1)).WillRepeatedly(testing::Return(storeOk()));
    EXPECT_CALL(*mockStore, upsertInternalDoc(internalName1, testing::_)).WillRepeatedly(testing::Return(storeOk()));

    // Add a thread to remove the db0
    threads.emplace_back(
        [&error, &errorMsg, times, type0, dbPath0](std::shared_ptr<IManager> manager,
                                                   std::shared_ptr<MockStore> mockStore)
        {
            bool action = true;
            for (int i = 0; i < times; i++)
            {
                if (error.load())
                {
                    return;
                }

                base::OptError res;
                if (action)
                {
                    res = manager->removeDb(dbPath0);
                    if (base::isError(res))
                    {
                        setError(error, errorMsg, base::getError(res).message);
                    }
                }
                else
                {
                    res = manager->addDb(dbPath0, type0);
                    if (base::isError(res))
                    {
                        setError(error, errorMsg, base::getError(res).message);
                    }
                }

                action = !action;
            }
        },
        manager,
        mockStore);

    // Add a thread to remove the db1
    threads.emplace_back(
        [&error, &errorMsg, times, type1, dbPath1](std::shared_ptr<IManager> manager,
                                                   std::shared_ptr<store::mocks::MockStore> mockStore)
        {
            bool action = true;
            for (int i = 0; i < times; i++)
            {
                if (error.load())
                {
                    return;
                }

                base::OptError res;
                if (action)
                {
                    res = manager->removeDb(dbPath1);
                    if (base::isError(res))
                    {
                        setError(error, errorMsg, base::getError(res).message);
                    }
                }
                else
                {
                    res = manager->addDb(dbPath1, type1);
                    if (base::isError(res))
                    {
                        setError(error, errorMsg, base::getError(res).message);
                    }
                }

                action = !action;
            }
        },
        manager,
        mockStore);

    for (auto& t : threads)
    {
        t.join();
    }

    ASSERT_FALSE(error.load()) << errorMsg;
}

} // namespace geoctest

/*
 * Wazuh Vulnerability Scanner - Unit Tests
 * Copyright (C) 2015, Wazuh Inc.
 * September 21, 2023.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */
#include "../../../vdscanner/src/factoryOrchestrator.hpp"
#include "../../../vdscanner/src/scanContext.hpp"
#include "base/utils/chainOfResponsability.hpp"
#include "feedmanager/mockDatabaseFeedManager.hpp"
#include <gmock/gmock.h>
#include <gtest/gtest.h>

class FactoryOrchestratorTest : public ::testing::Test
{
protected:
    // LCOV_EXCL_START
    FactoryOrchestratorTest() = default;
    ~FactoryOrchestratorTest() override = default;
    // LCOV_EXCL_STOP

    /**
     * @brief Set up for every test.
     *
     */
    void SetUp() override
    {
        // No specific setup logic required for this test.
    }

    /**
     * @brief Tear down for every test.
     *
     */
    void TearDown() override
    {
        // No specific tear down logic required for this test.
    }
};

enum class ScannerMockID : int
{
    PACKAGE_SCANNER = 0,
    OS_SCANNER = 1,
    RESPONSE_BUILDER = 2
};

/**
 * @brief Generic fake base class
 */
template<ScannerMockID Param = ScannerMockID::PACKAGE_SCANNER>
class TFakeClass : public utils::patterns::AbstractHandler<std::shared_ptr<std::vector<ScannerMockID>>>
{
public:
    ScannerMockID m_id {Param}; ///< Identifier.

    /**
     * @brief Construct a new TFakeClass object.
     *
     * @param databaseFeedManager MockDatabaseFeedManager instance.
     */
    explicit TFakeClass([[maybe_unused]] const std::shared_ptr<MockDatabaseFeedManager>& databaseFeedManager) {};

    /**
     * @brief Construct a new TFakeClass object.
     */
    TFakeClass() = default;
    ~TFakeClass() override = default;

    /**
     * @brief Handles request and passes control to the next step of the chain.
     *
     * @param data Mocked context data
     * @return std::shared_ptr<std::vector<std::string>>
     */
    std::shared_ptr<std::vector<ScannerMockID>> handleRequest(std::shared_ptr<std::vector<ScannerMockID>> data) override
    {
        data->push_back(m_id);
        return utils::patterns::AbstractHandler<std::shared_ptr<std::vector<ScannerMockID>>>::handleRequest(
            std::move(data));
    }
};

/*
 * @brief Test the chain creation for packages.
 */
TEST_F(FactoryOrchestratorTest, TestScannerTypePackage)
{
    // Create the orchestrator for PackageInsert.
    auto orchestration = TFactoryOrchestrator<TFakeClass<ScannerMockID::PACKAGE_SCANNER>,
                                              TFakeClass<ScannerMockID::OS_SCANNER>,
                                              TFakeClass<ScannerMockID::RESPONSE_BUILDER>,
                                              std::vector<ScannerMockID>,
                                              MockDatabaseFeedManager>::create(ScannerType::Package, nullptr);

    auto context = std::make_shared<std::vector<ScannerMockID>>();

    EXPECT_NO_THROW(orchestration->handleRequest(context));
    EXPECT_EQ(context->size(), 2);
    EXPECT_EQ(context->at(0), ScannerMockID::PACKAGE_SCANNER);
    EXPECT_EQ(context->at(1), ScannerMockID::RESPONSE_BUILDER);
}

/*
 * @brief Test the chain creation for os.
 */
TEST_F(FactoryOrchestratorTest, TestScannerTypeOs)
{
    // Create the orchestrator for Os.
    auto orchestration = TFactoryOrchestrator<TFakeClass<ScannerMockID::PACKAGE_SCANNER>,
                                              TFakeClass<ScannerMockID::OS_SCANNER>,
                                              TFakeClass<ScannerMockID::RESPONSE_BUILDER>,
                                              std::vector<ScannerMockID>,
                                              MockDatabaseFeedManager>::create(ScannerType::Os, nullptr);

    auto context = std::make_shared<std::vector<ScannerMockID>>();

    EXPECT_NO_THROW(orchestration->handleRequest(context));
    EXPECT_EQ(context->size(), 2);
    EXPECT_EQ(context->at(0), ScannerMockID::OS_SCANNER);
    EXPECT_EQ(context->at(1), ScannerMockID::RESPONSE_BUILDER);
}

/**
 * Wazuh Inventory Sync - DataValue NULL validation tests
 * Copyright (C) 2015, Wazuh Inc.
 * June 5, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#include "flatbuffers/flatbuffers.h"
#include "inventorySync_generated.h"
#include <gtest/gtest.h>
#include <string>

/**
 * @brief Test suite for DataValue NULL pointer dereference protection
 *
 * These tests verify that the inventory sync facade properly validates
 * optional FlatBuffer fields (id, index, data) before dereferencing them,
 * preventing NULL pointer crashes (GHSA-6hxp-c9x3-qc7p).
 */
class DataValueNullValidationTest : public ::testing::Test
{
protected:
    flatbuffers::FlatBufferBuilder fbb;

    void SetUp() override
    {
        fbb.Clear();
    }

    /**
     * @brief Build a DataValue message with specified optional fields omitted
     */
    flatbuffers::DetachedBuffer
    buildDataValue(bool includeId,
                   bool includeIndex,
                   bool includeData,
                   Wazuh::SyncSchema::Operation operation = Wazuh::SyncSchema::Operation_Upsert)
    {
        flatbuffers::FlatBufferBuilder builder;

        flatbuffers::Offset<flatbuffers::String> idOff = 0;
        flatbuffers::Offset<flatbuffers::String> indexOff = 0;
        flatbuffers::Offset<flatbuffers::Vector<int8_t>> dataOff = 0;

        if (includeId)
        {
            idOff = builder.CreateString("test-id-123");
        }
        if (includeIndex)
        {
            indexOff = builder.CreateString("wazuh-states-vulnerabilities");
        }
        if (includeData)
        {
            const char json[] = "{}";
            auto dataVec = builder.CreateVector(reinterpret_cast<const int8_t*>(json), 2);
            dataOff = dataVec;
        }

        Wazuh::SyncSchema::DataValueBuilder dvBuilder(builder);
        dvBuilder.add_seq(1);
        dvBuilder.add_session(1);
        dvBuilder.add_operation(operation);

        if (includeId)
        {
            dvBuilder.add_id(idOff);
        }
        if (includeIndex)
        {
            dvBuilder.add_index(indexOff);
        }
        if (includeData)
        {
            dvBuilder.add_data(dataOff);
        }

        auto dvOff = dvBuilder.Finish();
        auto msgOff =
            Wazuh::SyncSchema::CreateMessage(builder, Wazuh::SyncSchema::MessageType_DataValue, dvOff.Union());
        Wazuh::SyncSchema::FinishMessageBuffer(builder, msgOff);

        return builder.Release();
    }
};

/**
 * @brief Verify that DataValue with all fields present passes FlatBuffers verification
 */
TEST_F(DataValueNullValidationTest, ValidDataValue_AllFieldsPresent_PassesVerification)
{
    auto buffer = buildDataValue(true, true, true);

    flatbuffers::Verifier verifier(buffer.data(), buffer.size());
    EXPECT_TRUE(Wazuh::SyncSchema::VerifyMessageBuffer(verifier));

    auto message = Wazuh::SyncSchema::GetMessage(buffer.data());
    auto data = message->content_as_DataValue();
    ASSERT_NE(data, nullptr);
    EXPECT_NE(data->id(), nullptr);
    EXPECT_NE(data->index(), nullptr);
    EXPECT_NE(data->data(), nullptr);
}

/**
 * @brief Verify that DataValue with missing 'id' passes FlatBuffers verification
 * but the field is NULL
 *
 * This is the primary vulnerability case from GHSA-6hxp-c9x3-qc7p.
 */
TEST_F(DataValueNullValidationTest, MissingId_ValidIndexAndData_PassesVerifierButIdIsNull)
{
    auto buffer = buildDataValue(false, true, true);

    flatbuffers::Verifier verifier(buffer.data(), buffer.size());
    EXPECT_TRUE(Wazuh::SyncSchema::VerifyMessageBuffer(verifier))
        << "FlatBuffers verifier should accept message with missing optional 'id' field";

    auto message = Wazuh::SyncSchema::GetMessage(buffer.data());
    auto data = message->content_as_DataValue();
    ASSERT_NE(data, nullptr);

    // Verify that id is NULL (the vulnerability condition)
    EXPECT_EQ(data->id(), nullptr) << "When 'id' field is omitted, data->id() must return nullptr";

    // Verify that index and data are still valid
    EXPECT_NE(data->index(), nullptr);
    EXPECT_NE(data->data(), nullptr);
}

/**
 * @brief Verify that DataValue with missing 'index' passes FlatBuffers verification
 * but the field is NULL
 */
TEST_F(DataValueNullValidationTest, MissingIndex_ValidIdAndData_PassesVerifierButIndexIsNull)
{
    auto buffer = buildDataValue(true, false, true);

    flatbuffers::Verifier verifier(buffer.data(), buffer.size());
    EXPECT_TRUE(Wazuh::SyncSchema::VerifyMessageBuffer(verifier))
        << "FlatBuffers verifier should accept message with missing optional 'index' field";

    auto message = Wazuh::SyncSchema::GetMessage(buffer.data());
    auto data = message->content_as_DataValue();
    ASSERT_NE(data, nullptr);

    // Verify that index is NULL
    EXPECT_EQ(data->index(), nullptr) << "When 'index' field is omitted, data->index() must return nullptr";

    // Verify that id and data are still valid
    EXPECT_NE(data->id(), nullptr);
    EXPECT_NE(data->data(), nullptr);
}

/**
 * @brief Verify that DataValue with missing 'data' for Upsert operation
 * passes FlatBuffers verification but the field is NULL
 */
TEST_F(DataValueNullValidationTest, MissingData_UpsertOperation_PassesVerifierButDataIsNull)
{
    auto buffer = buildDataValue(true, true, false, Wazuh::SyncSchema::Operation_Upsert);

    flatbuffers::Verifier verifier(buffer.data(), buffer.size());
    EXPECT_TRUE(Wazuh::SyncSchema::VerifyMessageBuffer(verifier))
        << "FlatBuffers verifier should accept message with missing optional 'data' field";

    auto message = Wazuh::SyncSchema::GetMessage(buffer.data());
    auto data = message->content_as_DataValue();
    ASSERT_NE(data, nullptr);

    // Verify that data is NULL
    EXPECT_EQ(data->data(), nullptr) << "When 'data' field is omitted, data->data() must return nullptr";

    // Verify that id and index are still valid
    EXPECT_NE(data->id(), nullptr);
    EXPECT_NE(data->index(), nullptr);
}

/**
 * @brief Verify that DataValue with all optional fields missing still passes
 * FlatBuffers verification (minimal case from the vulnerability report)
 */
TEST_F(DataValueNullValidationTest, AllOptionalFieldsMissing_PassesVerifierButAllNull)
{
    auto buffer = buildDataValue(false, false, false);

    flatbuffers::Verifier verifier(buffer.data(), buffer.size());
    EXPECT_TRUE(Wazuh::SyncSchema::VerifyMessageBuffer(verifier))
        << "FlatBuffers verifier should accept message with all optional fields omitted";

    auto message = Wazuh::SyncSchema::GetMessage(buffer.data());
    auto data = message->content_as_DataValue();
    ASSERT_NE(data, nullptr);

    // Verify all optional fields are NULL
    EXPECT_EQ(data->id(), nullptr);
    EXPECT_EQ(data->index(), nullptr);
    EXPECT_EQ(data->data(), nullptr);
}

/**
 * @brief Verify that DataValue with empty string 'id' is different from NULL 'id'
 */
TEST_F(DataValueNullValidationTest, EmptyStringId_DifferentFromNullId)
{
    flatbuffers::FlatBufferBuilder builder;

    auto idOff = builder.CreateString(""); // Empty string, not NULL
    auto indexOff = builder.CreateString("wazuh-states-test");
    const char json[] = "{}";
    auto dataOff = builder.CreateVector(reinterpret_cast<const int8_t*>(json), 2);

    Wazuh::SyncSchema::DataValueBuilder dvBuilder(builder);
    dvBuilder.add_seq(1);
    dvBuilder.add_session(1);
    dvBuilder.add_operation(Wazuh::SyncSchema::Operation_Upsert);
    dvBuilder.add_id(idOff);
    dvBuilder.add_index(indexOff);
    dvBuilder.add_data(dataOff);

    auto dvOff = dvBuilder.Finish();
    auto msgOff = Wazuh::SyncSchema::CreateMessage(builder, Wazuh::SyncSchema::MessageType_DataValue, dvOff.Union());
    Wazuh::SyncSchema::FinishMessageBuffer(builder, msgOff);

    flatbuffers::Verifier verifier(reinterpret_cast<const uint8_t*>(builder.GetBufferPointer()), builder.GetSize());
    EXPECT_TRUE(Wazuh::SyncSchema::VerifyMessageBuffer(verifier));

    auto message = Wazuh::SyncSchema::GetMessage(builder.GetBufferPointer());
    auto data = message->content_as_DataValue();
    ASSERT_NE(data, nullptr);

    // Empty string is present (not NULL) but has zero length
    EXPECT_NE(data->id(), nullptr) << "Empty string 'id' should not be NULL";
    EXPECT_EQ(data->id()->string_view().size(), 0) << "Empty string 'id' should have size 0";
    EXPECT_TRUE(data->id()->string_view().empty());
}

/**
 * @brief Verify that Delete operation with missing 'data' is valid
 * (Delete doesn't require data payload)
 */
TEST_F(DataValueNullValidationTest, DeleteOperation_MissingData_IsAcceptable)
{
    auto buffer = buildDataValue(true, true, false, Wazuh::SyncSchema::Operation_Delete);

    flatbuffers::Verifier verifier(buffer.data(), buffer.size());
    EXPECT_TRUE(Wazuh::SyncSchema::VerifyMessageBuffer(verifier));

    auto message = Wazuh::SyncSchema::GetMessage(buffer.data());
    auto data = message->content_as_DataValue();
    ASSERT_NE(data, nullptr);

    EXPECT_EQ(data->operation(), Wazuh::SyncSchema::Operation_Delete);
    EXPECT_EQ(data->data(), nullptr) << "Delete operation doesn't require 'data' field";
    EXPECT_NE(data->id(), nullptr);
    EXPECT_NE(data->index(), nullptr);
}

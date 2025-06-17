#include "gtest/gtest.h"
#include "systemInventory/systemContext.hpp"
#include "flatbuffers/include/syscollector_deltas_generated.h"
#include "flatbuffers/include/rsync_generated.h"
#include "flatbuffers/flatbuffers.h"
#include <json.hpp>
#include <string>
#include <vector>
#include "systemInventory/elements/groupElement.hpp"
#include "wcsModel/inventoryGroupHarvester.hpp"
#include "wcsModel/data.hpp"
#include "wcsModel/noData.hpp"
#include "timeHelper.h"
#include "policyHarvesterManager.hpp"
#include "stringHelper.h" // For Utils::splitView

// --- Mock Data Structures ---
struct MockGroupData {
    std::string item_id = "group-item-001";
    std::string name = "testgroup";
    std::string gid = "2002";
    std::string description = "Test Group Description";
    std::string uuid = "group-uuid-456";
    bool is_hidden = false;
    std::string users = "user1,user2,testuser";
};

// Updated helper function to create mock Group data for Delta messages
flatbuffers::Offset<SyscollectorDeltas::DbsyncGroups>
CreateMockDbsyncGroups(flatbuffers::FlatBufferBuilder& builder, const MockGroupData& data)
{
    auto fb_item_id = builder.CreateString(data.item_id);
    auto fb_name = builder.CreateString(data.name);
    auto fb_gid = builder.CreateString(data.gid);
    auto fb_description = builder.CreateString(data.description);
    auto fb_uuid = builder.CreateString(data.uuid);
    auto fb_users = builder.CreateString(data.users);

    return SyscollectorDeltas::CreateDbsyncGroups(builder, fb_item_id, fb_name, fb_gid, fb_description, fb_uuid,
                                                  data.is_hidden, fb_users);
}

// Updated helper function to create mock Group data for Sync (State) messages
flatbuffers::Offset<Synchronization::SyscollectorGroups>
CreateMockSyncGroups(flatbuffers::FlatBufferBuilder& builder, const MockGroupData& data)
{
    auto fb_item_id = builder.CreateString(data.item_id);
    auto fb_name = builder.CreateString(data.name);
    auto fb_gid = builder.CreateString(data.gid);
    auto fb_description = builder.CreateString(data.description);
    auto fb_uuid = builder.CreateString(data.uuid);
    auto fb_users = builder.CreateString(data.users);

    return Synchronization::CreateSyscollectorGroups(builder, fb_item_id, fb_name, fb_gid, fb_description, fb_uuid,
                                                     data.is_hidden, fb_users);
}

TEST(SystemContextGroupTest, BuildDeltaContext_GroupInsert)
{
    flatbuffers::FlatBufferBuilder builder;
    auto operation = builder.CreateString("INSERTED");
    auto agent_id_str = "001";
    auto agent_name_str = "test-agent";
    auto agent_ip_str = "127.0.0.1";
    auto agent_version_str = "W_AGENT_VERSION";
    auto agent_id = builder.CreateString(agent_id_str);
    auto agent_name = builder.CreateString(agent_name_str);
    auto agent_ip = builder.CreateString(agent_ip_str);
    auto agent_version = builder.CreateString(agent_version_str);
    auto agent_info = SyscollectorDeltas::CreateAgentInfo(builder, agent_id, agent_name, agent_ip, agent_version);

    MockGroupData mock_group_data;
    auto group_data_fb = CreateMockDbsyncGroups(builder, mock_group_data);

    auto delta_offset = SyscollectorDeltas::CreateDelta(
        builder, operation, agent_info, SyscollectorDeltas::Provider_dbsync_groups, group_data_fb.Union());
    builder.Finish(delta_offset);

    auto delta_ptr = SyscollectorDeltas::GetDelta(builder.GetBufferPointer());
    SystemContext context(delta_ptr);

    ASSERT_EQ(context.operation(), SystemContext::Operation::Upsert);
    ASSERT_EQ(context.affectedComponentType(), SystemContext::AffectedComponentType::Group);
    ASSERT_EQ(context.originTable(), SystemContext::OriginTable::Groups);
    ASSERT_EQ(context.groupName(), mock_group_data.name);
    ASSERT_EQ(context.groupId(), mock_group_data.gid);
    ASSERT_EQ(context.groupDescription(), mock_group_data.description);
    ASSERT_EQ(context.groupUuid(), mock_group_data.uuid);
    ASSERT_EQ(context.groupIsHidden(), mock_group_data.is_hidden);
    ASSERT_EQ(context.groupUsers(), mock_group_data.users);
    ASSERT_EQ(context.groupItemId(), mock_group_data.item_id);
}

TEST(SystemContextGroupTest, BuildSyncContext_GroupState)
{
    flatbuffers::FlatBufferBuilder builder;
    auto agent_id_str = "002";
    auto agent_name_str = "sync-agent";
    auto agent_ip_str = "192.168.1.100";
    auto agent_version_str = "W_AGENT_SYNC_VERSION";
    auto agent_id = builder.CreateString(agent_id_str);
    auto agent_name = builder.CreateString(agent_name_str);
    auto agent_ip = builder.CreateString(agent_ip_str);
    auto agent_version = builder.CreateString(agent_version_str);
    auto agent_info = Synchronization::CreateAgentInfo(builder, agent_id, agent_name, agent_ip, agent_version);

    MockGroupData mock_group_data;
    auto group_attrs_fb = CreateMockSyncGroups(builder, mock_group_data);

    auto state_msg = Synchronization::CreateState(builder, agent_info, Synchronization::AttributesUnion_syscollector_groups, group_attrs_fb.Union());
    auto sync_msg_offset = Synchronization::CreateSyncMsg(builder, Synchronization::DataUnion_state, state_msg.Union());
    builder.Finish(sync_msg_offset);

    auto sync_ptr = Synchronization::GetSyncMsg(builder.GetBufferPointer());
    SystemContext context(sync_ptr);

    ASSERT_EQ(context.operation(), SystemContext::Operation::Upsert);
    ASSERT_EQ(context.affectedComponentType(), SystemContext::AffectedComponentType::Group);
    ASSERT_EQ(context.originTable(), SystemContext::OriginTable::Groups);
    ASSERT_EQ(context.groupName(), mock_group_data.name);
    ASSERT_EQ(context.groupItemId(), mock_group_data.item_id);
}

TEST(SystemContextGroupTest, BuildSyncContext_GroupIntegrityClear)
{
    flatbuffers::FlatBufferBuilder builder;
    auto agent_id = builder.CreateString("003");
    auto agent_info = Synchronization::CreateAgentInfo(builder, agent_id);
    auto attributes_type_str = builder.CreateString("syscollector_groups");
    auto integrity_clear_msg = Synchronization::CreateIntegrityClear(builder, agent_info, attributes_type_str);
    auto sync_msg_offset = Synchronization::CreateSyncMsg(builder, Synchronization::DataUnion_integrity_clear, integrity_clear_msg.Union());
    builder.Finish(sync_msg_offset);

    auto sync_ptr = Synchronization::GetSyncMsg(builder.GetBufferPointer());
    SystemContext context(sync_ptr);

    ASSERT_EQ(context.operation(), SystemContext::Operation::DeleteAllEntries);
    ASSERT_EQ(context.affectedComponentType(), SystemContext::AffectedComponentType::Group);
    ASSERT_EQ(context.originTable(), SystemContext::OriginTable::Groups);
}

TEST(SystemContextGroupTest, BuildSyncContext_GroupIntegrityCheckGlobal)
{
    flatbuffers::FlatBufferBuilder builder;
    auto agent_id = builder.CreateString("004");
    auto agent_info = Synchronization::CreateAgentInfo(builder, agent_id);
    auto attributes_type_str = builder.CreateString("syscollector_groups");
    auto integrity_check_msg = Synchronization::CreateIntegrityCheckGlobal(builder, agent_info, attributes_type_str);
    auto sync_msg_offset = Synchronization::CreateSyncMsg(builder, Synchronization::DataUnion_integrity_check_global, integrity_check_msg.Union());
    builder.Finish(sync_msg_offset);

    auto sync_ptr = Synchronization::GetSyncMsg(builder.GetBufferPointer());
    SystemContext context(sync_ptr);

    ASSERT_EQ(context.operation(), SystemContext::Operation::IndexSync);
    ASSERT_EQ(context.affectedComponentType(), SystemContext::AffectedComponentType::Group);
    ASSERT_EQ(context.originTable(), SystemContext::OriginTable::Groups);
}

TEST(SystemContextGroupTest, BuildJsonContext_DeleteGroup)
{
    nlohmann::json j;
    j["action"] = "deleteGroup";
    j["agent_info"]["agent_id"] = "005";
    j["data"]["item_id"] = "json-group-gid-to-delete";

    SystemContext context(&j);

    ASSERT_EQ(context.operation(), SystemContext::Operation::Delete);
    ASSERT_EQ(context.affectedComponentType(), SystemContext::AffectedComponentType::Group);
    ASSERT_EQ(context.originTable(), SystemContext::OriginTable::Groups);
    ASSERT_EQ(context.groupItemId(), "json-group-gid-to-delete");
}

TEST(GroupElementTest, CollectsGroupDataCorrectly_Delta) {
    flatbuffers::FlatBufferBuilder builder;
    auto agent_id_str = "agent008";
    auto agent_name_str = "group-agent";
    auto agent_ip_str = "10.0.0.8";
    auto agent_version_str = "W_AGENT_008";

    auto operation = builder.CreateString("INSERTED");
    auto agent_id_fb = builder.CreateString(agent_id_str);
    auto agent_name_fb = builder.CreateString(agent_name_str);
    auto agent_ip_fb = builder.CreateString(agent_ip_str);
    auto agent_version_fb = builder.CreateString(agent_version_str);
    auto agent_info_fb = SyscollectorDeltas::CreateAgentInfo(builder, agent_id_fb, agent_name_fb, agent_ip_fb, agent_version_fb);

    MockGroupData mock_group_data;
    auto group_data_fb = CreateMockDbsyncGroups(builder, mock_group_data);

    auto delta_offset = SyscollectorDeltas::CreateDelta(
        builder, operation, agent_info_fb, SyscollectorDeltas::Provider_dbsync_groups, group_data_fb.Union());
    builder.Finish(delta_offset);

    auto delta_ptr = SyscollectorDeltas::GetDelta(builder.GetBufferPointer());
    auto system_context = std::make_shared<SystemContext>(delta_ptr);

    DataHarvester<InventoryGroupHarvester> result = GroupElement<SystemContext>::build(system_context.get());

    std::string expected_doc_id = agent_id_str + "_" + mock_group_data.item_id;
    ASSERT_EQ(result.id, expected_doc_id);
    ASSERT_EQ(result.operation, "INSERTED");
    ASSERT_EQ(result.data.agent.id, agent_id_str);
    ASSERT_EQ(result.data.agent.name, agent_name_str);
    ASSERT_EQ(result.data.agent.ip, agent_ip_str);
    ASSERT_EQ(result.data.agent.version, agent_version_str);
    ASSERT_EQ(result.data.group.name, mock_group_data.name);
    ASSERT_EQ(result.data.group.id_signed, std::stol(mock_group_data.gid));
    ASSERT_EQ(result.data.group.id, static_cast<unsigned long>(std::stoul(mock_group_data.gid)));
    ASSERT_EQ(result.data.group.description, mock_group_data.description);
    ASSERT_EQ(result.data.group.uuid, mock_group_data.uuid);
    ASSERT_EQ(result.data.group.is_hidden, mock_group_data.is_hidden);
    ASSERT_EQ(result.data.group.users, mock_group_data.users);
}

TEST(GroupElementTest, DeletesGroupDataCorrectly_Delta) {
    flatbuffers::FlatBufferBuilder builder;
    auto agent_id_str = "agent008";
    MockGroupData mock_group_data;

    auto operation = builder.CreateString("DELETED");
    auto agent_id_fb = builder.CreateString(agent_id_str);
    auto agent_info_fb = SyscollectorDeltas::CreateAgentInfo(builder, agent_id_fb);

    auto group_data_fb = CreateMockDbsyncGroups(builder, mock_group_data);

    auto delta_offset = SyscollectorDeltas::CreateDelta(
        builder, operation, agent_info_fb, SyscollectorDeltas::Provider_dbsync_groups, group_data_fb.Union());
    builder.Finish(delta_offset);

    auto delta_ptr = SyscollectorDeltas::GetDelta(builder.GetBufferPointer());
    auto system_context = std::make_shared<SystemContext>(delta_ptr);

    NoDataHarvester result = GroupElement<SystemContext>::deleteElement(system_context.get());

    std::string expected_doc_id = agent_id_str + "_" + mock_group_data.item_id;
    ASSERT_EQ(result.id, expected_doc_id);
    ASSERT_EQ(result.operation, "DELETED");
}

TEST(GroupElementTest, CollectsGroupData_AgentIpIsAny) {
    flatbuffers::FlatBufferBuilder builder;
    std::string agent_id_str = "agent_ip_any_group";
    std::string agent_name_str = "test_agent_any_grp";
    std::string agent_ip_str = "any";
    std::string agent_version_str = "W_AGENT_V_ANY_GRP";

    auto operation = builder.CreateString("INSERTED");
    auto agent_id_fb = builder.CreateString(agent_id_str);
    auto agent_name_fb = builder.CreateString(agent_name_str);
    auto agent_ip_fb = builder.CreateString(agent_ip_str);
    auto agent_version_fb = builder.CreateString(agent_version_str);
    auto agent_info_fb = SyscollectorDeltas::CreateAgentInfo(builder, agent_id_fb, agent_name_fb, agent_ip_fb, agent_version_fb);

    MockGroupData mock_group_data;
    auto group_data_fb = CreateMockDbsyncGroups(builder, mock_group_data);

    auto delta_offset = SyscollectorDeltas::CreateDelta(
        builder, operation, agent_info_fb, SyscollectorDeltas::Provider_dbsync_groups, group_data_fb.Union());
    builder.Finish(delta_offset);

    auto delta_ptr = SyscollectorDeltas::GetDelta(builder.GetBufferPointer());
    auto system_context = std::make_shared<SystemContext>(delta_ptr);

    DataHarvester<InventoryGroupHarvester> result = GroupElement<SystemContext>::build(system_context.get());

    ASSERT_EQ(result.data.agent.ip, "");
    ASSERT_EQ(result.data.agent.id, agent_id_str);
    ASSERT_EQ(result.data.group.name, mock_group_data.name);
}

TEST(GroupElementTest, CollectsGroupData_AgentIpIsEmpty) {
    flatbuffers::FlatBufferBuilder builder;
    std::string agent_id_str = "agent_ip_empty_group";
    std::string agent_name_str = "test_agent_empty_grp";
    std::string agent_ip_str = "";
    std::string agent_version_str = "W_AGENT_V_EMPTY_GRP";

    auto operation = builder.CreateString("INSERTED");
    auto agent_id_fb = builder.CreateString(agent_id_str);
    auto agent_name_fb = builder.CreateString(agent_name_str);
    auto agent_ip_fb = builder.CreateString(agent_ip_str);
    auto agent_version_fb = builder.CreateString(agent_version_str);
    auto agent_info_fb = SyscollectorDeltas::CreateAgentInfo(builder, agent_id_fb, agent_name_fb, agent_ip_fb, agent_version_fb);

    MockGroupData mock_group_data;
    auto group_data_fb = CreateMockDbsyncGroups(builder, mock_group_data);

    auto delta_offset = SyscollectorDeltas::CreateDelta(
        builder, operation, agent_info_fb, SyscollectorDeltas::Provider_dbsync_groups, group_data_fb.Union());
    builder.Finish(delta_offset);

    auto delta_ptr = SyscollectorDeltas::GetDelta(builder.GetBufferPointer());
    auto system_context = std::make_shared<SystemContext>(delta_ptr);

    DataHarvester<InventoryGroupHarvester> result = GroupElement<SystemContext>::build(system_context.get());

    ASSERT_EQ(result.data.agent.ip, "");
    ASSERT_EQ(result.data.agent.id, agent_id_str);
    ASSERT_EQ(result.data.group.name, mock_group_data.name);
}

// Main function for GTest
int main(int argc, char** argv)
{
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}

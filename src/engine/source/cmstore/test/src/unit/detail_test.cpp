#include <gtest/gtest.h>

#include <base/utils/generator.hpp>
#include <cmstore/detail.hpp>

namespace
{

const std::string TYPE = "Decoder";

std::string validUUID()
{
    return base::utils::generators::generateUUIDv4();
}

std::string toUpperUUID(const std::string& uuid)
{
    std::string upper = uuid;
    for (char& c : upper)
    {
        c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
    }
    return upper;
}

} // namespace

TEST(DetailTest, ValidAndUniqueUUIDsDoNotThrow)
{
    const std::vector<std::string> uuids = {validUUID(), validUUID(), validUUID()};
    EXPECT_NO_THROW(cm::store::detail::findDuplicateOrInvalidUUID(uuids, TYPE));
}

TEST(DetailTest, EmptyListDoesNotThrow)
{
    EXPECT_NO_THROW(cm::store::detail::findDuplicateOrInvalidUUID({}, TYPE));
}

TEST(DetailTest, NonV4UUIDsDoNotThrow)
{
    // The identifier is opaque to the engine: any UUID version or format is accepted
    const std::vector<std::string> uuids = {"6093809a-6285-5cf8-9284-63bd68f796e9", // v5
                                            "00000000-0000-0000-0000-000000000000", // nil
                                            "0199a9f4-1b1e-7c3b-8f2a-2f9a1c0d4e5f", // v7
                                            "not-a-uuid"};
    EXPECT_NO_THROW(cm::store::detail::findDuplicateOrInvalidUUID(uuids, TYPE));
}

TEST(DetailTest, EmptyUUIDThrows)
{
    const std::vector<std::string> uuids = {""};
    EXPECT_THROW(cm::store::detail::findDuplicateOrInvalidUUID(uuids, TYPE), std::runtime_error);
}

TEST(DetailTest, EmptyUUIDErrorMessageContainsType)
{
    try
    {
        cm::store::detail::findDuplicateOrInvalidUUID({""}, TYPE);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_NE(std::string(e.what()).find(TYPE), std::string::npos);
        EXPECT_NE(std::string(e.what()).find("not a valid identifier"), std::string::npos);
    }
}

TEST(DetailTest, ControlCharacterUUIDThrows)
{
    EXPECT_THROW(cm::store::detail::findDuplicateOrInvalidUUID({validUUID(), "bad\nid"}, TYPE), std::runtime_error);
    EXPECT_THROW(cm::store::detail::findDuplicateOrInvalidUUID({"bad\tid"}, TYPE), std::runtime_error);
}

TEST(DetailTest, OversizedUUIDThrows)
{
    const std::string oversized(base::utils::generators::MAX_RESOURCE_ID_LENGTH + 1, 'a');
    EXPECT_THROW(cm::store::detail::findDuplicateOrInvalidUUID({oversized}, TYPE), std::runtime_error);
}

TEST(DetailTest, DuplicateUUIDThrows)
{
    const std::string uuid = validUUID();
    const std::vector<std::string> uuids = {uuid, uuid};
    EXPECT_THROW(cm::store::detail::findDuplicateOrInvalidUUID(uuids, TYPE), std::runtime_error);
}

TEST(DetailTest, DuplicateUUIDErrorMessageContainsDuplicateValue)
{
    const std::string uuid = validUUID();
    try
    {
        cm::store::detail::findDuplicateOrInvalidUUID({uuid, uuid}, TYPE);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_NE(std::string(e.what()).find(uuid), std::string::npos);
    }
}

TEST(DetailTest, IdsDifferingOnlyByCaseAreDistinct)
{
    // Identifiers are opaque and compared byte by byte: no case folding is applied
    const std::string lower = validUUID();
    const std::string upper = toUpperUUID(lower);
    ASSERT_NE(lower, upper);
    EXPECT_NO_THROW(cm::store::detail::findDuplicateOrInvalidUUID({lower, upper}, TYPE));
    EXPECT_NO_THROW(cm::store::detail::findDuplicateOrInvalidUUID({"ABC", "abc", "Abc"}, TYPE));
}

TEST(DetailTest, DuplicateNonUUIDIdentifierThrows)
{
    EXPECT_THROW(cm::store::detail::findDuplicateOrInvalidUUID({"custom/id_1", "custom/id_1"}, TYPE),
                 std::runtime_error);
}

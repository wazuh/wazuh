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
        if (c != '-')
        {
            c = static_cast<char>(std::toupper(static_cast<unsigned char>(c)));
        }
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

TEST(DetailTest, InvalidUUIDThrows)
{
    const std::vector<std::string> uuids = {"not-a-valid-uuid"};
    EXPECT_THROW(cm::store::detail::findDuplicateOrInvalidUUID(uuids, TYPE), std::runtime_error);
}

TEST(DetailTest, InvalidUUIDErrorMessageContainsValue)
{
    const std::string bad = "not-a-valid-uuid";
    try
    {
        cm::store::detail::findDuplicateOrInvalidUUID({bad}, TYPE);
        FAIL() << "Expected std::runtime_error";
    }
    catch (const std::runtime_error& e)
    {
        EXPECT_NE(std::string(e.what()).find(bad), std::string::npos);
    }
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

TEST(DetailTest, ExactDuplicateStillThrowsWhenCaseSensitiveDisabled)
{
    const std::string uuid = validUUID();
    EXPECT_THROW(cm::store::detail::findDuplicateOrInvalidUUID({uuid, uuid}, TYPE, false), std::runtime_error);
}

TEST(DetailTest, UppercaseUUIDRejectedBeforeCaseInsensitiveDuplicateCheck)
{
    const std::string lower = validUUID();
    const std::string upper = toUpperUUID(lower);
    EXPECT_THROW(cm::store::detail::findDuplicateOrInvalidUUID({lower, upper}, TYPE), std::runtime_error);
}

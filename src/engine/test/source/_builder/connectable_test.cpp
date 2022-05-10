#include "testUtils.hpp"

#include "_builder/connectable.hpp"

TEST(Connectable, test)
{
    auto conn = ConnectableOperation<int>::create();
    auto conn2 = ConnectableGroup::create();
    auto conn3 = ConnectableAsset::create();

    auto iconn1 = conn->getPtr<Connectable>();
    auto iconn2 = conn2->getPtr<Connectable>();
    auto iconn3 = conn3->getPtr<Connectable>();

    ASSERT_NE(iconn1, iconn2);
    ASSERT_NE(iconn1, iconn3);
    ASSERT_NE(iconn2, iconn3);

    ASSERT_NO_THROW(auto reconn1 = iconn1->getPtr<ConnectableOperation<int>>());
    ASSERT_NO_THROW(auto reconn2 = iconn2->getPtr<ConnectableGroup>());
    ASSERT_NO_THROW(auto reconn3 = iconn3->getPtr<ConnectableAsset>());

    ASSERT_THROW(auto rewrongconn1 = iconn1->getPtr<ConnectableGroup>(),
                 std::runtime_error);
    ASSERT_THROW(auto rewrongconn2 =
                     iconn2->getPtr<ConnectableOperation<int>>(),
                 std::runtime_error);
    ASSERT_THROW(auto rewrongconn3 =
                     iconn3->getPtr<ConnectableOperation<int>>(),
                 std::runtime_error);
}

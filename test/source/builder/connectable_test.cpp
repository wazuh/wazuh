#include <gtest/gtest.h>

#include <memory>
#include <string>
#include <vector>

#include "connectable.hpp"
#include "testUtils.hpp"

using namespace builder::internals;
using namespace std;
using namespace rxcpp;

struct FakeEvent
{
    int n;
    string str() const
    {
        return to_string(n);
    }
    FakeEvent(int n)
        : n {n}
    {
    }
};

using FakeEventType = shared_ptr<FakeEvent>;

TEST(ConnectableTest, Builds1)
{
    ASSERT_NO_THROW(Connectable<observable<FakeEventType>> {});
}

TEST(ConnectableTest, Builds2)
{
    ASSERT_NO_THROW(Connectable<observable<FakeEventType>> {"name"});
}

TEST(ConnectableTest, Builds3)
{
    ASSERT_NO_THROW(Connectable<observable<FakeEventType>>(
        "name", {}, [](auto o) { return o; }, {}));
}

TEST(ConnectableTest, AddInputConnectOperates)
{
    auto conn = Connectable<observable<FakeEventType>> {"name"};
    auto input =
        observable<>::just<FakeEventType>(make_shared<FakeEvent>(1)).publish();
    ASSERT_NO_THROW(conn.addInput(input));
    decltype(conn.connect()) end;
    ASSERT_NO_THROW(end = conn.connect());
    int expected = -1;
    end.subscribe([&](FakeEventType event) { expected = event->n; });
    input.connect();
    ASSERT_EQ(expected, 1);
}

TEST(ConnectableTest, TracerGraph)
{
    vector<Connectable<observable<FakeEventType>>> connectables;
    for (auto i = 0; i < 9; ++i)
    {
        // Build connectable as outputs so only one event will be sent by each conenctable
        connectables.push_back(
            Connectable<observable<FakeEventType>> {string("OUTPUT_")+std::to_string(i)});
    }

    // Manually build graph
    auto input =
        observable<>::just<FakeEventType>(make_shared<FakeEvent>(1)).publish();
    //     conn0
    //     /   \
    // conn1   conn8
    //     \   /
    //     conn2
    //     /    \
    //    /     conn4
    //    |     /   \
    //    | conn5   conn7
    //    |     \   /
    //    |     conn6
    //     \    /
    //     conn3
    connectables[0].addInput(input);
    auto obs = connectables[0].connect();
    obs = obs.publish().ref_count();
    connectables[1].addInput(obs);
    connectables[8].addInput(obs);
    obs = connectables[1].connect();
    connectables[2].addInput(obs);
    obs = connectables[8].connect();
    connectables[2].addInput(obs);
    obs = connectables[2].connect();
    obs = obs.publish().ref_count();
    connectables[3].addInput(obs);
    connectables[4].addInput(obs);
    obs = connectables[4].connect().publish().ref_count();
    connectables[5].addInput(obs);
    connectables[7].addInput(obs);
    obs = connectables[5].connect();
    connectables[6].addInput(obs);
    obs = connectables[7].connect();
    connectables[6].addInput(obs);
    obs = connectables[6].connect();
    connectables[3].addInput(obs);
    auto end = connectables[3].connect();

    // Push only sent events by each connectable in expected order
    vector<int> expected;
    for (auto &conn : connectables)
    {
        conn.m_tracer.m_out.subscribe(
            [&, name = conn.m_name](string msg)
            {
                //GTEST_COUT << msg << endl;
                if(msg.find("sent") != string::npos)
                    expected.push_back(stoi(name.substr(name.size()-1)));
            });
    }
    end.subscribe();
    input.connect();
    ASSERT_EQ(expected.size(), 9);
    for (auto i = 0; i < 9; ++i){
        ASSERT_EQ(expected[i], i);
    }
}

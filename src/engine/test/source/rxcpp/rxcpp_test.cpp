#include "rxcpp_test.hpp"
#include "_builder.hpp"
#include "_connectable.hpp"
#include "_graph.hpp"
#include "rxcpp/rx-test.hpp"
#include "rxcpp/rx.hpp"
#include "gtest/gtest.h"
#include "json/json.hpp"
#include <algorithm>
#include <chrono>
#include <exception>
#include <iostream>
#include <random>
#include <string>
#include <thread>

#define GTEST_COUT std::cerr << "[          ] [ INFO ] "

// namespace rx
// {
// using namespace rxcpp;
// using namespace rxcpp::operators;
// using namespace rxcpp::sources;
// using namespace rxcpp::util;
// } // namespace rx

template <class T> using Op_t = std::function<T(T)>;
template <class T> using Obs_t = rxcpp::observable<T>;
template <class T> using Sub_t = rxcpp::subscriber<T>;
template <class T> using Con_t = Connectable<Obs_t<T>>;

template <class Value, class Error> auto fallibleBuilder(rxcpp::subscriber<Error> error)
{
    return [=](Op_t<Value> fn)
    {
        return [=](Sub_t<Value> dest)
        {
            return rxcpp::make_subscriber<Value>(dest, rxcpp::make_observer_dynamic<Value>(
                                                           [=](Value n)
                                                           {
                                                               try
                                                               {
                                                                   dest.on_next(fn(n));
                                                               }
                                                               catch (Error e)
                                                               {
                                                                   error.on_next(e);
                                                               }
                                                           },
                                                           [=](std::exception_ptr e) { dest.on_error(e); },
                                                           [=]() { dest.on_completed(); }));
        };
    };
}

template <class Value> Obs_t<Value> dynamic_merge(std::vector<Obs_t<Value>> v)
{
    return rxcpp::observable<>::iterate(v).flat_map([](Obs_t<Value> o) { return o; });
}

TEST(RXCPP, NormalFail)
{

    auto obs = rxcpp::observable<>::create<int>(
        [](rxcpp::subscriber<int> s)
        {
            s.on_next(1);
            s.on_next(2);
        });
    obs.filter([](int i) -> bool { throw std::runtime_error("Filter failed for some reason"); })
        .subscribe([](int i) { GTEST_COUT << std::to_string(i) << std::endl; },
                   [](std::exception_ptr e) { GTEST_COUT << "error!" << std::endl; },
                   []() { GTEST_COUT << "completed" << std::endl; });
}

TEST(RXCPP, FallibleOperation)
{
    auto general_error_handler = [=](std::exception_ptr e)
    {
        try
        {
            rethrow_exception(e);
        }
        catch (const std::exception & ex)
        {
            GTEST_COUT << "General error!! " << ex.what() << std::endl;
        }
    };
    auto domain_error_handler = [=](std::logic_error e) { GTEST_COUT << e.what() << std::endl; };

    auto errSubs = rxcpp::make_subscriber<std::logic_error>(domain_error_handler, general_error_handler,
                                                            []() { GTEST_COUT << "completed" << std::endl; });

    auto obs = rxcpp::observable<>::create<int>(
        [](rxcpp::subscriber<int> s)
        {
            s.on_next(1);
            s.on_next(2);
            s.on_next(3);
            s.on_next(4);
            s.on_next(5);
            s.on_next(6);
            s.on_next(7);
        });

    auto fallible = fallibleBuilder<int, std::logic_error>(errSubs);

    obs.lift<int>(fallible(
                      [](int i) -> int
                      {
                          if (i % 2 == 0)
                          {
                              throw std::logic_error("logic_error thrown on lambda ");
                          }
                          if (i == 5)
                          {
                              throw std::runtime_error("shit happens");
                          }
                          return i;
                      }))
        .subscribe([](int i) { GTEST_COUT << std::to_string(i) << std::endl; }, general_error_handler,
                   []() { GTEST_COUT << "completed" << std::endl; });
}

TEST(RXCPP, AnyCombinatorMerge)
{
    auto general_error_handler = [=](std::exception_ptr e)
    {
        try
        {
            rethrow_exception(e);
        }
        catch (const std::exception & ex)
        {
            GTEST_COUT << "General error!! " << ex.what() << std::endl;
        }
    };

    auto domain_error_handler = [=](std::logic_error e)
    { GTEST_COUT << "Error subscriber: " << e.what() << std::endl; };

    auto errSubs = rxcpp::make_subscriber<std::logic_error>(domain_error_handler, general_error_handler,
                                                            []() { GTEST_COUT << "completed" << std::endl; });

    auto obs = rxcpp::observable<>::create<int>(
                   [](rxcpp::subscriber<int> s)
                   {
                       s.on_next(1);
                       s.on_next(2);
                       s.on_next(3);
                       s.on_next(4);
                       s.on_next(5);
                       s.on_next(6);
                       s.on_next(7);
                   })
                   .publish();

    auto fallible = fallibleBuilder<int, std::logic_error>(errSubs);

    auto fOdds = fallible(
        [](int i)
        {
            if (i % 2 == 0)
            {
                throw std::logic_error("Filtered odd number");
            }
            return i;
        });
    auto fEvens = fallible(
        [](int i)
        {
            if (i % 2 != 0)
            {
                throw std::logic_error("Filtered even number");
            }
            return i;
        });

    auto left = obs.lift<int>(fOdds);
    auto right = obs.lift<int>(fEvens);
    auto merged = left.merge(right);

    merged.subscribe([](int i) { GTEST_COUT << "output " << std::to_string(i) << std::endl; }, general_error_handler,
                     []() { GTEST_COUT << "completed" << std::endl; });
    obs.connect();
}

TEST(RXCPP, AnyCombinatorRefCount)
{
    auto general_error_handler = [=](std::exception_ptr e)
    {
        try
        {
            rethrow_exception(e);
        }
        catch (const std::exception & ex)
        {
            GTEST_COUT << "General error!! " << ex.what() << std::endl;
        }
    };

    auto domain_error_handler = [=](std::logic_error e)
    { GTEST_COUT << "Error subscriber: " << e.what() << std::endl; };

    auto errSubs = rxcpp::make_subscriber<std::logic_error>(domain_error_handler, general_error_handler,
                                                            []() { GTEST_COUT << "completed" << std::endl; });

    auto obs = rxcpp::observable<>::create<int>(
                   [](rxcpp::subscriber<int> s)
                   {
                       s.on_next(1);
                       s.on_next(2);
                       s.on_next(3);
                       s.on_next(4);
                       s.on_next(5);
                       s.on_next(6);
                       s.on_next(7);
                   })
                   .publish();

    auto fallible = fallibleBuilder<int, std::logic_error>(errSubs);

    auto fOdds = fallible(
        [](int i)
        {
            if (i != 2)
            {
                throw std::logic_error("Filtered odd number");
            }
            return i;
        });

    auto fEvens = fallible(
        [](int i)
        {
            if (i != 4)
            {
                throw std::logic_error("Filtered even number");
            }
            return i;
        });

    auto left = obs.lift<int>(fOdds);
    auto right = obs.lift<int>(fEvens);
    auto merged = left.merge(right);

    auto connect_on_subscribe = merged.ref_count(obs);
    connect_on_subscribe.subscribe([](int i) { GTEST_COUT << "output " << std::to_string(i) << std::endl; },
                                   general_error_handler, []() { GTEST_COUT << "completed" << std::endl; });
    // obs.connect();
}

TEST(RXCPP, AnyCombinatorMergeErrorValues)
{
    // an implementation of an or operation

    // error sin
    auto errorsink = rxcpp::make_subscriber<std::string>([](auto err) { GTEST_COUT << err << std::endl; },
                                                         []() { GTEST_COUT << "completed" << std::endl; });

    // we have a single source of events
    Obs_t<int> source = rxcpp::observable<>::range(1, 10);

    // from this observable, we create two derived observables
    Obs_t<int> left = source.filter(
        [=](int i)
        {
            if (i % 2 == 0)
            {
                return true;
            }
            else
            {
                errorsink.on_next(std::to_string(i) + " does not pass the filter");
            }
            return false;
        });
    Obs_t<int> right = source.filter([](int i) { return i == 5; });

    left.merge(right).subscribe([](int v) { GTEST_COUT << "Got " << std::to_string(v) << std::endl; },
                                []() { GTEST_COUT << "OnCompleted" << std::endl; });
}

template <class E> class OS
{
private:
    std::string m_name;
    rxcpp::observer<E> m_obs;

public:
    OS(std::string n) : m_name(n){};
    rxcpp::subjects::subject<E> m_subj;
};

template <class E> OS<E> copyOS(OS<E> os)
{
    return os;
}

TEST(RXCPP, ObjectSlicing)
{

    OS<json::Document> src("src");
    OS<json::Document> dst(" dst ");
    auto copied = copyOS(src);
    dst.m_subj.get_observable().subscribe(copied.m_subj.get_subscriber());
    copied.m_subj.get_observable().subscribe(dst.m_subj.get_subscriber());
}

TEST(RXCPP, ServerErrorSinkAsync)
{
    using Obs_t = rxcpp::observable<int>;
    using Sub_t = rxcpp::subscriber<Obs_t>;

    std::random_device rd;  // obtain a random number from hardware
    std::mt19937 gen(rd()); // seed the generator
    std::uniform_int_distribution<> distr(50, 300);

    auto general_error_handler = [=](std::exception_ptr e)
    {
        try
        {
            rethrow_exception(e);
        }
        catch (const std::exception & ex)
        {
            GTEST_COUT << "General error!! " << ex.what() << std::endl;
        }
    };
    auto domain_error_handler = [=](std::logic_error e) { GTEST_COUT << "error sink " << e.what() << std::endl; };

    auto errorsink = rxcpp::make_subscriber<std::logic_error>(
        domain_error_handler, general_error_handler, []() { GTEST_COUT << "error sink completed" << std::endl; });

    auto ph = fallibleBuilder<int, std::logic_error>(errorsink);

    // The server emits an observable per connection received
    int expected = 10;
    auto server = rxcpp::observable<>::create<Obs_t>(
        [&](Sub_t s)
        {
            for (int i = 0; i < expected; i++)
            {
                auto w = distr(gen);
                auto next = rxcpp::observable<>::timer(std::chrono::milliseconds(w))
                                .lift<int>(ph(
                                    [=](int) -> int
                                    {
                                        if (i == 5)
                                        {
                                            throw std::logic_error(
                                                "Some connections just fail. Or there is an error parsing the message");
                                        }
                                        return i * 1000 + w;
                                    }));
                s.on_next(next);
            }
        });
    int got{0};

    server.flat_map([](Obs_t o) { return o; })
        .subscribe(
            [&](int i)
            {
                GTEST_COUT << std::to_string(i) << std::endl;
                got++;
            },
            []() { GTEST_COUT << " All connections completed!" << std::endl; });

    ASSERT_EQ(got, expected - 1);
}

template <class V> class Val
{
public:
    V val;
    Val(V v) : val(v){};
    friend inline bool operator<(const Val & lhs, const Val & rhs)
    {
        return lhs.val < rhs.val;
    }
    friend inline std::ostream & operator<<(std::ostream & os, const Val & rhs)
    {
        os << rhs.val;
        return os;
    }
};

auto test1()
{
    auto g = _graph::Graph<Val<std::string>>();
    g.node(Val(std::string("a")));
    g.node(Val(std::string("b")));
    g.node(Val(std::string("c")));
    g.node(Val(std::string("d")));
    g.node(Val(std::string("e")));

    g.add_edge(Val(std::string("a")), Val(std::string("b")));
    g.add_edge(Val(std::string("a")), Val(std::string("c")));
    g.add_edge(Val(std::string("a")), Val(std::string("d")));
    return g;
}

TEST(RXCPP, NewGraph)
{
    auto g = test1();
    g.node(Val(std::string("f")));
    // g.remove_edge(Val(std::string("a")), Val(std::string("d")));
    g.inject(Val(std::string("a")), Val(std::string("f")));
    GTEST_COUT << "visit" << std::endl;
    g.visit([](auto n) { GTEST_COUT << n.first.val << std::endl; });
    GTEST_COUT << "leaves" << std::endl;
    g.leaves([](auto n) { GTEST_COUT << n.val << std::endl; });
    std::cerr << g.print().str() << std::endl;
}

TEST(RXCPP, MultiMerge)
{
    auto general_error_handler = [=](std::exception_ptr e)
    {
        try
        {
            rethrow_exception(e);
        }
        catch (const std::exception & ex)
        {
            GTEST_COUT << "General error!! " << ex.what() << std::endl;
        }
    };

    auto domain_error_handler = [=](std::logic_error e)
    { GTEST_COUT << "Error subscriber: " << e.what() << std::endl; };

    auto errSubs = rxcpp::make_subscriber<std::logic_error>(domain_error_handler, general_error_handler,
                                                            []() { GTEST_COUT << "completed" << std::endl; });

    auto obs = rxcpp::observable<>::create<int>(
                   [](rxcpp::subscriber<int> s)
                   {
                       s.on_next(1);
                       s.on_next(2);
                       s.on_next(3);
                       s.on_next(4);
                       s.on_next(5);
                       s.on_next(6);
                       s.on_next(7);
                   })
                   .publish();

    auto fallible = fallibleBuilder<int, std::logic_error>(errSubs);

    auto pb = fallible([](int i) { return i + 1; });
    std::vector<Obs_t<int>> l;
    for (int i = 0; i < 10; i++)
    {
        l.push_back(obs.lift<int>(pb));
    }
    auto merged = dynamic_merge<int>(l);

    merged.subscribe([](int i) { GTEST_COUT << "output " << std::to_string(i) << std::endl; }, general_error_handler,
                     []() { GTEST_COUT << "completed" << std::endl; });
    obs.connect();
}

template <class Value>
void visit(Obs_t<Value> source, Con_t<Value> root, std::map<Con_t<Value>, std::set<Con_t<Value>>> & edges,
           Sub_t<Value> s)
{
    auto itr = edges.find(root);
    if (itr == edges.end())
    {
        throw std::invalid_argument("Value root is not in the graph");
    }

    // Visit node
    Con_t<Value> node = itr->first;
    if (node.inputs.size() == 0)
        node.add_input(source);

    Obs_t<Value> obs = node.connect();

    // Add obs as an input to the childs
    for (Con_t<Value> n : itr->second)
    {
        n.add_input(obs);
    }

    // Visit childs
    for (auto & n : itr->second)
    {
        visit(obs, n, edges, s);
    }
    if (itr->second.size() == 0)
    {
        obs.subscribe(s);
    }
}

TEST(RXCPP, DecoderManualConnectExample)
{
    using Event_t = json::Document;
    using Obs_t = rxcpp::observable<json::Document>;
    using Sub_t = rxcpp::subscriber<json::Document>;
    using Con_t = Connectable<Obs_t>;

    int expected = 10;
    auto source = rxcpp::observable<>::create<Event_t>(
                      [expected](const Sub_t s)
                      {
                          for (int i = 0; i < expected; i++)
                          {
                              auto val = std::to_string(i);
                              if (i % 2 == 0)
                                  s.on_next(Event_t(R"({"type": "int", "field": "odd", "value": 0})"));
                              else
                                  s.on_next(Event_t(R"({"type": "int", "field": "even", "value": 1})"));
                          }
                          s.on_completed();
                      })
                      .publish();

    auto sub = rxcpp::subjects::subject<Event_t>();

    auto subscriber = rxcpp::make_subscriber<Event_t>([](Event_t v) { GTEST_COUT << "Got " << v.str() << std::endl; },
                                                      []() { GTEST_COUT << "OnCompleted" << std::endl; });

    auto env = _builder::environmentBuilder<FakeCatalog>(FakeCatalog(), "environment_6");
    std::map<Con_t, std::set<Con_t>> res = env.get();
    visit<Event_t>(sub.get_observable(), Con_t("decoders_input"), res, subscriber);

    source.subscribe(sub.get_subscriber());
    source.connect();
    std::cerr << env.print().str() << std::endl;
}

TEST(RXCPP, DynamicOR)
{
    using Sub_t = rxcpp::subscriber<int>;
    using Obs_t = rxcpp::observable<int>;
    using Op_t = std::function<Obs_t(Obs_t)>;

    std::vector<Op_t> oplist;

    oplist.push_back([](Obs_t o) -> Obs_t
                     { return o.filter([](auto i) { return i == 1; }).map([](auto i) { return i; }); });
    oplist.push_back([](Obs_t o) -> Obs_t
                     { return o.filter([](auto i) { return i == 2; }).map([](auto i) { return i; }); });
    oplist.push_back([](Obs_t o) -> Obs_t
                     { return o.filter([](auto i) { return i == 3; }).map([](auto i) { return i; }); });
    oplist.push_back([](Obs_t o) -> Obs_t
                     { return o.filter([](auto i) { return i == 4; }).map([](auto i) { return i * 10; }); });

    // merge approach
    auto or_combinator = [=](Obs_t input) -> Obs_t
    {
        auto connect = [=](Obs_t in, std::vector<Op_t> remaining, auto & connect_ref) -> Obs_t
        {
            Op_t current = remaining.back();
            remaining.pop_back();
            Obs_t currObs = current(input);
            if (remaining.size() == 0)
            {
                return currObs;
            }
            return connect_ref(currObs, remaining, connect_ref).merge(currObs);
        };
        return connect(input, oplist, connect);
    };

    // flat_map approach
    auto or_combinator_flat = [=](Obs_t input) -> Obs_t
    {
        std::vector<Obs_t> inputs;
        for (auto op : oplist)
        {
            inputs.push_back(op(input));
        }
        return rxcpp::observable<>::iterate(inputs).flat_map([](auto o) { return o; });
    };

    // subscriber bridge, not-safe, currently core dumps
    auto or_combinator_subscr = [=](Obs_t input) -> Obs_t
    {
        std::vector<Obs_t> inputs;
        for (auto op : oplist)
        {
            inputs.push_back(op(input));
        }
        return rxcpp::observable<>::create<int>(
            [=](Sub_t s)
            {
                int last{0};
                for (auto o : inputs)
                {
                    o.subscribe(
                        [&](auto i)
                        {
                            if (i != last)
                                last = i;
                                s.on_next(i);
                        }, [&](){ s.on_completed(); });
                }
            });
    };
    auto source = rxcpp::observable<>::range(1, 4).publish();

    // auto obs = or_combinator(source);
    auto obs = or_combinator_flat(source);
    // auto obs = or_combinator_subscr(source);
    obs.subscribe([](auto i) { std::cerr << std::to_string(i) << std::endl; },
                  []() { std::cerr << "completed" << std::endl; });
    source.connect();
}

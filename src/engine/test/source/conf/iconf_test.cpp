#include <conf/iconf.hpp>

#include <gtest/gtest.h>

struct DummyConf
{
    std::map<std::string, std::any> m_map{
        {"int", 10},
        {"str", std::string{"str"}},
    };

    template<typename T>
    T get(const std::string& key) const
    {
        return std::any_cast<T>(m_map.at(key));
    }
};

struct WrongConf
{
};

TEST(IconfTest, Test)
{

    // conf::IConf<DummyConf> conf;
    // auto intValue = conf.get<int>("int");
    // std::cout << intValue << std::endl;

    // auto strValue = conf.get<std::string>("str");
    // std::cout << strValue << std::endl;
}

#include <vector>
#include <string_view>
#include <tuple>

using namespace std;

class EngineDefinition
{
    public:
        EngineDefinition(const string_view& name, const vector<string_view>& components): name(name), components(components){};
        string_view name;
        vector<string_view> components;
};



class Configuration
{
    public:
        void add_engine(const string_view& name, const vector<string_view>& components)
        {
            this->engines.push_back(EngineDefinition(name, components));
        };
        vector<EngineDefinition>::const_iterator cbegin() const noexcept
        {
            return this->engines.cbegin();
        };
        vector<EngineDefinition>::const_iterator cend() const noexcept
        {
            return this->engines.cend();
        };


    private:
        vector<EngineDefinition> engines;
};

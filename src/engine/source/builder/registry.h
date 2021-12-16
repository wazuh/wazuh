#include <iostream>
#include <map>
#include <string>

using namespace std;

class Registry {

    public:
        void registerBuilder (string name, string builder){
            if (registry.count(name)>0) {
                throw invalid_argument("Key already stored on map");
            }
            else{
                pair <string,string> item (name,builder);
                registry.insert(item);
            }
        };
        string getBuilder (string name){
            map<string,string>::iterator item = registry.find(name);
            if (item == registry.end()) {
                throw invalid_argument("Key cant be found on map");
            }
            else{
                return item->second;
            }
        };
        bool isEmpty () {
            return registry.empty();
        };

    private:
        map<string,string> registry;
};

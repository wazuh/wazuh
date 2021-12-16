#include <iostream>
#include <map>
#include <string>

using namespace std;

class Registry {

    map<string,string> REGISTRY;

    public:

        Registry () {

        }

        void registerItem (string name, string callable){

            pair <string,string> item (name,callable);
            REGISTRY.insert(item);
        }

        string getBuilder (string name){
            string result = REGISTRY.find(name)->second;
            return result;
        }

        map<string,string> getRegistry () {
            return REGISTRY;
        }


};

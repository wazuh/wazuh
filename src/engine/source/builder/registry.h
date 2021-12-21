#pragma once

#include <map>
#include <string>

#include "builder.h"

using namespace std;

namespace builder
{
    class Registry
    {
        public:
            /**
             * @brief Get instance.
             * Implementes <a href="https://en.wikipedia.org/wiki/Talk%3ASingleton_pattern#Meyers_singleton">Meyer's singleton</a>.
             *
             * @return Registry instance reference.
             */
            static Registry& instance();

            /**
            * @brief Deleted to implement Meyer's singleton.
            */
            Registry(const Registry&) = delete;

            /**
            * @brief Deleted to implement Meyer's singleton.
            */
            Registry& operator = (const Registry&) = delete;

            /**
             * @brief Register a Builder.
             *
             * @param builder_id Unique Builder id string.
             * @param builder Builder object.
             */
            void register_builder(const string& builder_id, const Builder& builder);

            /**
             * @brief Get the builder object
             *
             * @param builder_id Builder name to be retreived.
             * @return Builder object.
             */
            const builder::Builder* get_builder(const string& builder_id) const;

        private:
            /**
             * @brief Declared private to implement Meyer's singleton.
             */
            Registry() {}

            /**
            * @brief Declared private to implement Meyer's singleton.
            */
            ~Registry() {}

            /**
             * @brief registry that holds all Builders.
             */
            map<string, const builder::Builder*> registry;
    };
};

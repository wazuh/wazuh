#pragma once

#include <string_view>
#include <rxcpp/rx.hpp>
#include <nlohmann/json.hpp>

using json = nlohmann::json;
using namespace std;
using namespace rxcpp;


/**
 * @brief Defines all functionality related to builders.
 *
 * It defines all classes and functions needed to construct runtime objects that implement the operations
 * described by an enviroment, with it engines (Decoders, Rules, Filters...).
 *
 */
namespace builder
{

    /**
     * @brief Get the enviroment object.
     *
     * It queries the Catalog in order to access the objects needed to build all observable operations
     * and returns a composed observable with them.
     *
     * @param enviroment_id Name of the enviroment to be built.
     * @return observable<json>
     */
    observable<json> get_enviroment(const string_view& enviroment_id);

    /**
     * Builder base class.
     *
     * This class implements the polimorphism needed to include various builder types in the Registry
     * and implements the registration on all Builder classes.
     *
     * This class can not be instantiated directly.
     */
    class Builder
    {
        protected:
            /**
             * @brief Construct a new Builder object.
             *
             * @param builder_id Name with which it will be registered.
             */
            explicit Builder(const string& builder_id);

        public:
            /**
            * @brief Deleted for safety.
            */
            Builder() = delete;

            /**
            * @brief Deleted for safety.
            */
            Builder(const Builder&) = delete;

            /**
            * @brief Deleted for safety.
            */
            Builder& operator = (const Builder&) = default;
    };

    /**
    * JsonBuilder class.
    *
    * This class implements the builders wich need a json object as input.
    */
    class JsonBuilder: public Builder
    {
        public:
            /**
             * @brief Construct a new Json Builder object.
             *
             * @param builder_id Name with which it will be registered.
             * @param build Function that implements the build operation.
             */
            JsonBuilder(const string& builder_id, observable<json> (*build)(const observable<json>&, const json&));

            /**
             * @brief Implepents build operation.
             *
             * @param input_observable Observable on which the transformations will be applied.
             * @param input_json Json object with transformations definitions.
             * @return Composed observable with transformations.
             */
            observable<json> (*build)(const observable<json>& input_observable, const json& input_json);

            /**
             * @brief Deleted for safety.
             */
            JsonBuilder() = delete;

            /**
            * @brief Deleted for safety.
            */
            JsonBuilder(const JsonBuilder&) = delete;

            /**
             * @brief Deleted for safety.
             */
            JsonBuilder& operator = (const JsonBuilder&) = delete;
    };

    /**
    * MultiJsonBuilder class.
    *
    * This class implements the builders wich need multiple json objects as input.
    */
    class MultiJsonBuilder: public Builder
    {
        public:
            /**
            * @brief Construct a new MultiJsonBuilder object.
            *
            * @param builder_id Name with which it will be registered.
            * @param build Function that implements the build operation.
            */
            MultiJsonBuilder(const string&, observable<json> (*)(const observable<json>&, const vector<json>&));


            /**
             * @brief Implepents build operation.
             *
             * @param input_observable Observable on which the transformations will be applied.
             * @param input_json_vector Json objects with transformations definitions.
             * @return Composed observable with transformations.
             */
            observable<json> (*build)(const observable<json>& input_observable, const vector<json>& input_json_vector);

            /**
            * @brief Deleted for safety.
            */
            MultiJsonBuilder() = delete;

            /**
            * @brief Deleted for safety.
            */
            MultiJsonBuilder(const MultiJsonBuilder&) = delete;

            /**
            * @brief Deleted for safety.
            */
            MultiJsonBuilder& operator = (const MultiJsonBuilder&) = delete;
    };
};

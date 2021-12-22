#pragma once

#include <string>
#include <exception>
#include <rxcpp/rx.hpp>
#include <nlohmann/json.hpp>


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
    rxcpp::observable<nlohmann::json> get_enviroment(const std::string& enviroment_id);

    /**
     * @brief Base class to allow polymorphism in the Registry.
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
            explicit Builder(const std::string& builder_id);

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
    * @brief Implements json input builders.
    *
    * This class implements the builders wich need a json object as input.
    */
    class JsonBuilder: public Builder
    {
        public:
            /**
             * @brief Construct a new JsonBuilder object.
             *
             * @param builder_id Name with which it will be registered.
             * @param build Function that implements the build operation.
             */
            JsonBuilder(const std::string& builder_id, rxcpp::observable<nlohmann::json> (*build)(const rxcpp::observable<nlohmann::json>&, const nlohmann::json&));

            /**
             * @brief Implepents build operation.
             *
             * @param input_observable Observable on which the transformations will be applied.
             * @param input_json Json object with transformations definitions.
             * @return Composed observable with transformations.
             */
            rxcpp::observable<nlohmann::json> (*build)(const rxcpp::observable<nlohmann::json>& input_observable, const nlohmann::json& input_json);

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
    * @brief Implements multiple jsons input builders.
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
            MultiJsonBuilder(const std::string&, rxcpp::observable<nlohmann::json> (*)(const rxcpp::observable<nlohmann::json>&, const std::vector<nlohmann::json>&));


            /**
             * @brief Implepents build operation.
             *
             * @param input_observable Observable on which the transformations will be applied.
             * @param input_json_vector Json objects with transformations definitions.
             * @return Composed observable with transformations.
             */
            rxcpp::observable<nlohmann::json> (*build)(const rxcpp::observable<nlohmann::json>& input_observable, const std::vector<nlohmann::json>& input_json_vector);

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

    /**
     * @brief Exception thrown on building errors.
     *
     * Thrown by specific instances of Builder when method build encounters errors and the object
     * can't be built.
     *
     */
    class BuildError: public std::exception
    {
        public:
            /**
             * @brief Construct a new BuildError object.
             *
             * @param builder_name name of the Builder instance.
             * @param message descriptive message of the error.
             */
            BuildError(const std::string& builder_name, const std::string& message);
            const char* what() const noexcept override;

        private:
            std::string m_builder_name;
            std::string m_message;
    };
};

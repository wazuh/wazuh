#ifndef _SCHEMA_VALIDATOR_HPP
#define _SCHEMA_VALIDATOR_HPP

// Define EXPORTED for any platform
#ifdef _WIN32
#ifdef WIN_EXPORT
#define EXPORTED __declspec(dllexport)
#else
#define EXPORTED __declspec(dllimport)
#endif
#elif __GNUC__ >= 4
#define EXPORTED __attribute__((visibility("default")))
#else
#define EXPORTED
#endif

#include <memory>
#include <string>
#include <vector>
#include <json.hpp>

namespace SchemaValidator
{
    /**
     * @brief Result of a schema validation operation
     */
    struct EXPORTED ValidationResult
    {
        bool isValid;                      ///< True if the message is valid
        std::vector<std::string> errors;   ///< List of validation errors

        ValidationResult()
            : isValid(true)
        {
        }
    };

    /**
     * @brief Abstract interface for schema validators
     *
     * Implementations can validate JSON messages against schemas.
     */
    class EXPORTED ISchemaValidatorEngine
    {
        public:
            /**
             * @brief Virtual destructor
             */
            virtual ~ISchemaValidatorEngine() = default;

            /**
             * @brief Validate a JSON message against the loaded schema
             *
             * @param message JSON message as string
             * @return ValidationResult Result of the validation
             */
            virtual ValidationResult validate(const std::string& message) = 0;

            /**
             * @brief Validate a JSON message against the loaded schema
             *
             * @param message JSON message as nlohmann::json object
             * @return ValidationResult Result of the validation
             */
            virtual ValidationResult validate(const nlohmann::json& message) = 0;

            /**
             * @brief Get the schema name
             *
             * @return std::string Schema name (derived from index pattern)
             */
            virtual std::string getSchemaName() const = 0;
    };

    /**
     * @brief Schema validator for Elasticsearch index template mappings
     *
     * This class validates JSON messages against Elasticsearch index template mappings
     * loaded from schema files. It supports type checking, nested objects, and strict mode.
     */
    class EXPORTED SchemaValidatorEngine : public ISchemaValidatorEngine
    {
        public:
            /**
             * @brief Construct a new Schema Validator object
             */
            SchemaValidatorEngine();

            /**
             * @brief Destroy the Schema Validator object
             */
            ~SchemaValidatorEngine() override;

            /**
             * @brief Load a schema from a JSON string
             *
             * @param schemaContent JSON schema content as string
             * @return true if schema was loaded successfully
             * @return false if schema loading failed
             */
            bool loadSchemaFromString(const std::string& schemaContent);

            /**
             * @brief Validate a JSON message against the loaded schema
             *
             * @param message JSON message as string
             * @return ValidationResult Result of the validation
             */
            ValidationResult validate(const std::string& message) override;

            /**
             * @brief Validate a JSON message against the loaded schema
             *
             * @param message JSON message as nlohmann::json object
             * @return ValidationResult Result of the validation
             */
            ValidationResult validate(const nlohmann::json& message) override;

            /**
             * @brief Get the schema name
             *
             * @return std::string Schema name (derived from index pattern)
             */
            std::string getSchemaName() const override;

        private:
            class Impl;
            std::unique_ptr<Impl> m_impl;
    };

    /**
     * @brief Factory class for creating schema validators
     *
     * This class manages schema validators for different indices and provides
     * a convenient way to get validators for specific index patterns.
     */
    class EXPORTED SchemaValidatorFactory
    {
        public:
            /**
             * @brief Get the singleton instance
             *
             * @return SchemaValidatorFactory& Reference to the singleton instance
             */
            static SchemaValidatorFactory& getInstance();

            /**
             * @brief Initialize the factory with embedded schema resources or custom validators
             *
             * If customValidators is provided, uses those validators instead of loading
             * from embedded resources. This allows dependency injection for testing.
             *
             * @param customValidators Optional map of index pattern -> validator instances.
             *                         If empty, loads schemas from embedded resources.
             * @return true if initialization was successful
             * @return false if initialization failed
             */
            bool initialize(std::map<std::string, std::shared_ptr<ISchemaValidatorEngine>> customValidators = {});

            /**
             * @brief Get a validator for a specific index pattern
             *
             * @param indexPattern Index pattern (e.g., "wazuh-states-inventory-hardware")
             * @return std::shared_ptr<ISchemaValidatorEngine> Validator instance or nullptr if not found
             */
            std::shared_ptr<ISchemaValidatorEngine> getValidator(const std::string& indexPattern);

            /**
             * @brief Check if the factory is initialized
             *
             * @return true if initialized
             * @return false otherwise
             */
            bool isInitialized() const;

            /**
             * @brief Reset the singleton instance (for testing purposes)
             *
             * This allows tests to inject a mock validator by clearing
             * the singleton and letting tests control initialization.
             */
            void reset();

        private:
            SchemaValidatorFactory();
            ~SchemaValidatorFactory();
            SchemaValidatorFactory(const SchemaValidatorFactory&) = delete;
            SchemaValidatorFactory& operator=(const SchemaValidatorFactory&) = delete;

            class Impl;
            std::unique_ptr<Impl> m_impl;
    };

} // namespace SchemaValidator

#endif // _SCHEMA_VALIDATOR_HPP

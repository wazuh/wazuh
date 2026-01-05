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
     * @brief Schema validator for Elasticsearch index template mappings
     *
     * This class validates JSON messages against Elasticsearch index template mappings
     * loaded from schema files. It supports type checking, nested objects, and strict mode.
     */
    class EXPORTED SchemaValidatorEngine
    {
    public:
        /**
         * @brief Construct a new Schema Validator object
         */
        SchemaValidatorEngine();

        /**
         * @brief Destroy the Schema Validator object
         */
        ~SchemaValidatorEngine();

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
        ValidationResult validate(const std::string& message);

        /**
         * @brief Validate a JSON message against the loaded schema
         *
         * @param message JSON message as nlohmann::json object
         * @return ValidationResult Result of the validation
         */
        ValidationResult validate(const nlohmann::json& message);

        /**
         * @brief Get the schema name
         *
         * @return std::string Schema name (derived from index pattern)
         */
        std::string getSchemaName() const;

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
         * @brief Initialize the factory with embedded schema resources
         *
         * Loads schemas from embedded resources (compiled into the binary).
         *
         * @return true if initialization was successful
         * @return false if initialization failed
         */
        bool initialize();

        /**
         * @brief Get a validator for a specific index pattern
         *
         * @param indexPattern Index pattern (e.g., "wazuh-states-sca")
         * @return std::shared_ptr<SchemaValidatorEngine> Validator instance or nullptr if not found
         */
        std::shared_ptr<SchemaValidatorEngine> getValidator(const std::string& indexPattern);

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

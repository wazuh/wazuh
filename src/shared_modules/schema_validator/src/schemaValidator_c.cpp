#include "schemaValidator_c.h"
#include "schemaValidator.hpp"
#include <cstring>
#include <string>

extern "C" {

    bool schema_validator_initialize(void)
    {
        try
        {
            auto& factory = SchemaValidator::SchemaValidatorFactory::getInstance();
            return factory.initialize();
        }
        catch (...)
        {
            return false;
        }
    }

    bool schema_validator_is_initialized(void)
    {
        try
        {
            auto& factory = SchemaValidator::SchemaValidatorFactory::getInstance();
            return factory.isInitialized();
        }
        catch (...)
        {
            return false;
        }
    }

    bool schema_validator_validate(const char* indexPattern,
                                   const char* message,
                                   char** errorMessage)
    {
        if (!indexPattern || !message)
        {
            return false;
        }

        // Initialize output parameter
        if (errorMessage)
        {
            *errorMessage = nullptr;
        }

        try
        {
            auto& factory = SchemaValidator::SchemaValidatorFactory::getInstance();

            if (!factory.isInitialized())
            {
                return true; // If not initialized, consider it valid (backward compatibility)
            }

            auto validator = factory.getValidator(std::string(indexPattern));

            if (!validator)
            {
                return true; // No validator for this index, consider it valid
            }

            auto result = validator->validate(std::string(message));

            if (!result.isValid)
            {
                // Build error message
                if (errorMessage)
                {
                    std::string errors;

                    for (const auto& error : result.errors)
                    {
                        if (!errors.empty())
                        {
                            errors += "\n";
                        }

                        errors += error;
                    }

                    *errorMessage = strdup(errors.c_str());
                }

                return false;
            }

            // Message is valid
            return true;
        }
        catch (...)
        {
            return false;
        }
    }

} // extern "C"

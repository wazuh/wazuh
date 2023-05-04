#ifndef _OP_BUILDER_SPECIFIC_HLP_H
#define _OP_BUILDER_SPECIFIC_HLP_H

#include <any>

#include <baseTypes.hpp>
#include <defs/idefinitions.hpp>

#include "expression.hpp"

//*************************************************
//*         HLP Specific parser Helpers           *
//*************************************************

namespace builder::internals::builders
{

/**
 * @brief Helper function of boolean parser from HLP
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression Expression of the operation
 * @throw std::runtime_error If the number of parameters is not 1 (source)
 */
base::Expression opBuilderSpecificHLPBoolParse(const std::string& targetField,
                                               const std::string& rawName,
                                               const std::vector<std::string>& rawParameters,
                                               std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Helper function of byte parser from HLP
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression Expression of the operation
 * @throw std::runtime_error If the number of parameters is not 1 (source)
 */
base::Expression opBuilderSpecificHLPByteParse(const std::string& targetField,
                                               const std::string& rawName,
                                               const std::vector<std::string>& rawParameters,
                                               std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Helper function of long parser from HLP
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression Expression of the operation
 * @throw std::runtime_error If the number of parameters is not 1 (source)
 */
base::Expression opBuilderSpecificHLPLongParse(const std::string& targetField,
                                               const std::string& rawName,
                                               const std::vector<std::string>& rawParameters,
                                               std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Helper function of float parser from HLP
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression Expression of the operation
 * @throw std::runtime_error If the number of parameters is not 1 (source)
 */
base::Expression opBuilderSpecificHLPFloatParse(const std::string& targetField,
                                                const std::string& rawName,
                                                const std::vector<std::string>& rawParameters,
                                                std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Helper function of double parser from HLP
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression Expression of the operation
 * @throw std::runtime_error If the number of parameters is not 1 (source)
 */
base::Expression opBuilderSpecificHLPDoubleParse(const std::string& targetField,
                                                 const std::string& rawName,
                                                 const std::vector<std::string>& rawParameters,
                                                 std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Helper function of base64 parser from HLP
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression Expression of the operation
 * @throw std::runtime_error If the number of parameters is not 1 (source)
 */
base::Expression opBuilderSpecificHLPBinaryParse(const std::string& targetField,
                                                 const std::string& rawName,
                                                 const std::vector<std::string>& rawParameters,
                                                 std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Helper function of date parser from HLP
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPDateParse(const std::string& targetField,
                                               const std::string& rawName,
                                               const std::vector<std::string>& rawParameters,
                                               std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Helper function of ip parser from HLP
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPIPParse(const std::string& targetField,
                                             const std::string& rawName,
                                             const std::vector<std::string>& rawParameters,
                                             std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Helper function of uri parser from HLP
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPURIParse(const std::string& targetField,
                                              const std::string& rawName,
                                              const std::vector<std::string>& rawParameters,
                                              std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Helper function of user agent parser from HLP
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPUserAgentParse(const std::string& targetField,
                                                    const std::string& rawName,
                                                    const std::vector<std::string>& rawParameters,
                                                    std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Helper function of FQDN parser from HLP
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPFQDNParse(const std::string& targetField,
                                               const std::string& rawName,
                                               const std::vector<std::string>& rawParameters,
                                               std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Helper function of file path parser from HLP
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPFilePathParse(const std::string& targetField,
                                                   const std::string& rawName,
                                                   const std::vector<std::string>& rawParameters,
                                                   std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Helper function of json parser from HLP
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPJSONParse(const std::string& targetField,
                                               const std::string& rawName,
                                               const std::vector<std::string>& rawParameters,
                                               std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Helper function of xml parser from HLP
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPXMLParse(const std::string& targetField,
                                              const std::string& rawName,
                                              const std::vector<std::string>& rawParameters,
                                              std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Helper function of csv parser from HLP
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPCSVParse(const std::string& targetField,
                                              const std::string& rawName,
                                              const std::vector<std::string>& rawParameters,
                                              std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Helper function of dsv parser from HLP
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPDSVParse(const std::string& targetField,
                                              const std::string& rawName,
                                              const std::vector<std::string>& rawParameters,
                                              std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Helper function of key value parser from HLP
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPKeyValueParse(const std::string& targetField,
                                                   const std::string& rawName,
                                                   const std::vector<std::string>& rawParameters,
                                                   std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Helper function of quoted parser from HLP
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPQuotedParse(const std::string& targetField,
                                                 const std::string& rawName,
                                                 const std::vector<std::string>& rawParameters,
                                                 std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Helper function of between parser from HLP
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression Expression of the operation
 */
base::Expression opBuilderSpecificHLPBetweenParse(const std::string& targetField,
                                                  const std::string& rawName,
                                                  const std::vector<std::string>& rawParameters,
                                                  std::shared_ptr<defs::IDefinitions> definitions);

/**
 * @brief Helper function of alphanumeric parser from HLP
 *
 * @param targetField target field of the helper
 * @param rawName name of the helper as present in the raw definition
 * @param rawParameters vector of parameters as present in the raw definition
 * @param definitions handler with definitions
 * @return base::Expression Expression of the operation
 * @throw std::runtime_error If the number of parameters is not 1 (source)
 */
base::Expression opBuilderSpecificHLPAlphanumericParse(const std::string& targetField,
                                                       const std::string& rawName,
                                                       const std::vector<std::string>& rawParameters,
                                                       std::shared_ptr<defs::IDefinitions> definitions);

} // namespace builder::internals::builders

#endif // _OP_BUILDER_SPECIFIC_HLP_H

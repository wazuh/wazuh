#ifndef _BUILDER_BUILDERS_OPTRANSFORM_HLP_HPP
#define _BUILDER_BUILDERS_OPTRANSFORM_HLP_HPP

#include "builders/types.hpp"

//*************************************************
//*         HLP Specific parser Helpers           *
//*************************************************

namespace builder::builders::optransform
{

/**
 * @brief Helper function of boolean parser from HLP
 *
 * @param targetField target field of the helper
 * @param opArgs vector of parameters as present in the raw definition
 * @param buildCtx Build context
 * @return TransformOp Expression of the operation
 * @throw std::runtime_error If the number of parameters is not 1 (source)
 */
TransformOp boolParseBuilder(const Reference& targetField,
                             const std::vector<OpArg>& opArgs,
                             const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Helper function of byte parser from HLP
 *
 * @param targetField target field of the helper
 * @param opArgs vector of parameters as present in the raw definition
 * @param buildCtx Build context
 * @return TransformOp Expression of the operation
 * @throw std::runtime_error If the number of parameters is not 1 (source)
 */
TransformOp byteParseBuilder(const Reference& targetField,
                             const std::vector<OpArg>& opArgs,
                             const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Helper function of long parser from HLP
 *
 * @param targetField target field of the helper
 * @param opArgs vector of parameters as present in the raw definition
 * @param buildCtx Build context
 * @return TransformOp Expression of the operation
 * @throw std::runtime_error If the number of parameters is not 1 (source)
 */
TransformOp longParseBuilder(const Reference& targetField,
                             const std::vector<OpArg>& opArgs,
                             const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Helper function of float parser from HLP
 *
 * @param targetField target field of the helper
 * @param opArgs vector of parameters as present in the raw definition
 * @param buildCtx Build context
 * @return TransformOp Expression of the operation
 * @throw std::runtime_error If the number of parameters is not 1 (source)
 */
TransformOp floatParseBuilder(const Reference& targetField,
                              const std::vector<OpArg>& opArgs,
                              const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Helper function of double parser from HLP
 *
 * @param targetField target field of the helper
 * @param opArgs vector of parameters as present in the raw definition
 * @param buildCtx Build context
 * @return TransformOp Expression of the operation
 * @throw std::runtime_error If the number of parameters is not 1 (source)
 */
TransformOp doubleParseBuilder(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Helper function of base64 parser from HLP
 *
 * @param targetField target field of the helper
 * @param opArgs vector of parameters as present in the raw definition
 * @param buildCtx Build context
 * @return TransformOp Expression of the operation
 * @throw std::runtime_error If the number of parameters is not 1 (source)
 */
TransformOp binaryParseBuilder(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Helper function of date parser from HLP
 *
 * @param targetField target field of the helper
 * @param opArgs vector of parameters as present in the raw definition
 * @param buildCtx Build context
 * @return TransformOp Expression of the operation
 */
TransformOp dateParseBuilder(const Reference& targetField,
                             const std::vector<OpArg>& opArgs,
                             const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Helper function of ip parser from HLP
 *
 * @param targetField target field of the helper
 * @param opArgs vector of parameters as present in the raw definition
 * @param buildCtx Build context
 * @return TransformOp Expression of the operation
 */
TransformOp ipParseBuilder(const Reference& targetField,
                           const std::vector<OpArg>& opArgs,
                           const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Helper function of uri parser from HLP
 *
 * @param targetField target field of the helper
 * @param opArgs vector of parameters as present in the raw definition
 * @param buildCtx Build context
 * @return TransformOp Expression of the operation
 */
TransformOp uriParseBuilder(const Reference& targetField,
                            const std::vector<OpArg>& opArgs,
                            const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Helper function of user agent parser from HLP
 *
 * @param targetField target field of the helper
 * @param opArgs vector of parameters as present in the raw definition
 * @param buildCtx Build context
 * @return TransformOp Expression of the operation
 */
TransformOp userAgentParseBuilder(const Reference& targetField,
                                  const std::vector<OpArg>& opArgs,
                                  const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Helper function of FQDN parser from HLP
 *
 * @param targetField target field of the helper
 * @param opArgs vector of parameters as present in the raw definition
 * @param buildCtx Build context
 * @return TransformOp Expression of the operation
 */
TransformOp fqdnParseBuilder(const Reference& targetField,
                             const std::vector<OpArg>& opArgs,
                             const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Helper function of file path parser from HLP
 *
 * @param targetField target field of the helper
 * @param opArgs vector of parameters as present in the raw definition
 * @param buildCtx Build context
 * @return TransformOp Expression of the operation
 */
TransformOp filePathParseBuilder(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Helper function of json parser from HLP
 *
 * @param targetField target field of the helper
 * @param opArgs vector of parameters as present in the raw definition
 * @param buildCtx Build context
 * @return TransformOp Expression of the operation
 */
TransformOp jsonParseBuilder(const Reference& targetField,
                             const std::vector<OpArg>& opArgs,
                             const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Helper function of xml parser from HLP
 *
 * @param targetField target field of the helper
 * @param opArgs vector of parameters as present in the raw definition
 * @param buildCtx Build context
 * @return TransformOp Expression of the operation
 */
TransformOp xmlParseBuilder(const Reference& targetField,
                            const std::vector<OpArg>& opArgs,
                            const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Helper function of csv parser from HLP
 *
 * @param targetField target field of the helper
 * @param opArgs vector of parameters as present in the raw definition
 * @param buildCtx Build context
 * @return TransformOp Expression of the operation
 */
TransformOp csvParseBuilder(const Reference& targetField,
                            const std::vector<OpArg>& opArgs,
                            const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Helper function of dsv parser from HLP
 *
 * @param targetField target field of the helper
 * @param opArgs vector of parameters as present in the raw definition
 * @param buildCtx Build context
 * @return TransformOp Expression of the operation
 */
TransformOp dsvParseBuilder(const Reference& targetField,
                            const std::vector<OpArg>& opArgs,
                            const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Helper function of key value parser from HLP
 *
 * @param targetField target field of the helper
 * @param opArgs vector of parameters as present in the raw definition
 * @param buildCtx Build context
 * @return TransformOp Expression of the operation
 */
TransformOp keyValueParseBuilder(const Reference& targetField,
                                 const std::vector<OpArg>& opArgs,
                                 const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Helper function of quoted parser from HLP
 *
 * @param targetField target field of the helper
 * @param opArgs vector of parameters as present in the raw definition
 * @param buildCtx Build context
 * @return TransformOp Expression of the operation
 */
TransformOp quotedParseBuilder(const Reference& targetField,
                               const std::vector<OpArg>& opArgs,
                               const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Helper function of between parser from HLP
 *
 * @param targetField target field of the helper
 * @param opArgs vector of parameters as present in the raw definition
 * @param buildCtx Build context
 * @return TransformOp Expression of the operation
 */
TransformOp betweenParseBuilder(const Reference& targetField,
                                const std::vector<OpArg>& opArgs,
                                const std::shared_ptr<const IBuildCtx>& buildCtx);

/**
 * @brief Helper function of alphanumeric parser from HLP
 *
 * @param targetField target field of the helper
 * @param opArgs vector of parameters as present in the raw definition
 * @param buildCtx Build context
 * @return TransformOp Expression of the operation
 * @throw std::runtime_error If the number of parameters is not 1 (source)
 */
TransformOp alphanumericParseBuilder(const Reference& targetField,
                                     const std::vector<OpArg>& opArgs,
                                     const std::shared_ptr<const IBuildCtx>& buildCtx);

} // namespace builder::builders::optransform

#endif // _BUILDER_BUILDERS_OPTRANSFORM_HLP_HPP

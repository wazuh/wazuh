#ifndef _BUILDER_BUILDERS_TYPES_HPP
#define _BUILDER_BUILDERS_TYPES_HPP

#include <functional>
#include <memory>
#include <string>

#include <baseTypes.hpp>
#include <schemf/ischema.hpp>

namespace builder::builders
{
/**
 * @brief Control flags for the runtime
 *
 */
struct RuntimeState
{
    bool trace;   // Active/Inactive trace messages
    bool sandbox; // Active/Inactive test mode
    bool check;   // Active/Inactive hard type enforcement mode
};

/**
 * @brief Context for the builder
 *
 */
struct BuildContext
{
    std::string assetName;  // Name of the current asset being built
    std::string policyName; // Name of the current policy being built
    std::string stageName;  // Name of the current stage being built
};

using OpBuilder = std::function<base::EngineOp(std::string,                      // targetField
                                               std::string,                      // name
                                               std::vector<std::string>,         // rawParameters
                                               std::shared_ptr<schemf::ISchema>, // schema
                                               std::shared_ptr<RuntimeState>,    // runState
                                               std::shared_ptr<BuildContext>)>;  // buildCtx
} // namespace builder::builders

#endif // _BUILDER_BUILDERS_TYPES_HPP

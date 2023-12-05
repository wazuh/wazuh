#ifndef _BUILDER2_REGISTER_HPP
#define _BUILDER2_REGISTER_HPP

#include <memory>

#include "builder.hpp"
#include "builders/iregistry.hpp"

// Filter builders
#include "builders/opfilter/filter.hpp"

// Map builders
#include "builders/opmap/map.hpp"

// Stage builders
#include "builders/stage/check.hpp"
#include "builders/stage/map.hpp"
#include "builders/stage/normalize.hpp"
#include "builders/stage/parse.hpp"

namespace builder::detail
{

template<typename Registry>
void registerOpBuilders(const std::shared_ptr<Registry>& registry, const BuilderDeps& deps)
{
    // Filter builders
    registry->template add<builders::OpBuilderEntry>(
        "filter", {builders::opfilter::filterValidator(), builders::opfilter::filterBuilder});

    // Map builders
    registry->template add<builders::OpBuilderEntry>("map", {std::make_shared<builders::ValidationToken>(), builders::opmap::mapBuilder});
}

template<typename Registry>
void registerStageBuilders(const std::shared_ptr<Registry>& registry, const BuilderDeps& deps)
{
    registry->template add<builders::StageBuilder>("check", builders::checkBuilder);
    registry->template add<builders::StageBuilder>("map", builders::mapBuilder);
    registry->template add<builders::StageBuilder>("normalize", builders::normalizeBuilder);
    registry->template add<builders::StageBuilder>("parse",
                                                   builders::getParseBuilder(deps.logpar, deps.logparDebugLvl));
}

} // namespace builder::detail

#endif // _BUILDER2_REGISTER_HPP

#include "enrichment.hpp"

#include <exception>
#include <fmt/format.h>

#include <fastmetrics/registry.hpp>

#include "syntax.hpp"

namespace
{
constexpr std::string_view JPATH_ORIGIN_SPACE = "/wazuh/space/name"; ///< wazuh.space.name
const std::string ENRICHMENT_SPACE_TRACEABLE_NAME = "enrichment/OriginSpace";
const std::string DISCARDED_EVENTS_FILTER_TRACEABLE_NAME = "filter/DiscardedEvents";
const std::string CLEANUP_DECODER_VARIABLES_TRACEABLE_NAME = "cleanup/DecoderTemporaryVariables";

constexpr auto POSITIVE_INDEXED_BY_DISCARDED_TRUE =
    "Discard_event() -> Success: Event will be indexed (index_discarded_events=true)";
constexpr auto NEGATIVE_INDEXED_BY_DISCARDED_TRUE_FIELD_FALSE =
    "Discard_event() -> Failure: Event won't be indexed (wazuh.space.event_discarded=true and "
    "index_discarded_events=false)";
constexpr auto POSITIVE_INDEXED_BY_DISCARDED_FALSE =
    "Discard_event() -> Success: Event will be indexed (wazuh.space.event_discarded=false)";

} // namespace
namespace builder::builders::enrichment
{

std::pair<base::Expression, std::string> getSpaceEnrichment(const cm::store::dataType::Policy& policy, bool isTestMode)
{
    // Setting origin space

    auto op = base::Term<base::EngineOp>::create(
        ENRICHMENT_SPACE_TRACEABLE_NAME,
        [originSpace = policy.getOriginSpace(), isTestMode](base::Event event) -> base::result::Result<base::Event>
        {
            event->setString(originSpace, JPATH_ORIGIN_SPACE);
            if (isTestMode)
            {
                return base::result::makeSuccess<decltype(event)>(event, "[map: $wazuh.space.name] -> Success");
            }
            return base::result::makeSuccess<decltype(event)>(event);
        });

    return std::make_pair(makeTraceableSuccessExpression(op, isTestMode), ENRICHMENT_SPACE_TRACEABLE_NAME);
}

std::pair<base::Expression, std::string>
getDiscardedEventsFilter(const cm::store::dataType::Policy& policy,
                         bool isTestMode,
                         const std::shared_ptr<fastmetrics::ICounter>& discardedCounter)
{
    const bool shouldIndex = policy.shouldIndexDiscardedEvents();
    const auto discardFieldPath = json::Json::formatJsonPath(syntax::asset::discard::TARGET_FIELD);

    auto op = base::Term<base::EngineOp>::create(
        DISCARDED_EVENTS_FILTER_TRACEABLE_NAME,
        [shouldIndex, discardFieldPath, isTestMode, discardedCounter](base::Event event) -> base::result::Result<base::Event>
        {
            // Policy enables indexing of discarded events
            if (shouldIndex)
            {
                if (isTestMode)
                {
                    return base::result::makeSuccess<decltype(event)>(event, POSITIVE_INDEXED_BY_DISCARDED_TRUE);
                }
                return base::result::makeSuccess<decltype(event)>(event);
            }

            // Check if the discard field exists and is true
            auto discardValue = event->getBool(discardFieldPath);
            if (discardValue && discardValue.value())
            {
                discardedCounter->add(1);
                if (isTestMode)
                {
                    return base::result::makeFailure<decltype(event)>(event,
                                                                      NEGATIVE_INDEXED_BY_DISCARDED_TRUE_FIELD_FALSE);
                }
                return base::result::makeFailure<decltype(event)>(event);
            }

            if (isTestMode)
            {
                return base::result::makeSuccess<decltype(event)>(event, POSITIVE_INDEXED_BY_DISCARDED_FALSE);
            }
            return base::result::makeSuccess<decltype(event)>(event);
        });

    return std::make_pair(makeTraceableSuccessExpression(op, isTestMode), DISCARDED_EVENTS_FILTER_TRACEABLE_NAME);
}

base::Expression postOutputUnclassifiedCounter(const std::string& spaceName,
                                               std::shared_ptr<fastmetrics::ICounter> unclassifiedCounter)
{
    return base::Term<base::EngineOp>::create(
        "postOutputUnclassified",
        [unclassifiedCounter](base::Event event) -> base::result::Result<base::Event>
        {
            try
            {
                if (event->size(syntax::asset::DECODERS_PATH) == 1)
                {
                    unclassifiedCounter->add(1);
                }
            }
            catch (...)
            {
                // Ignore size() errors
            }
            return base::result::makeSuccess<decltype(event)>(event);
        });
}

std::pair<base::Expression, std::string> getCleanupDecoderVariables(bool enabled, bool isTestMode)
{
    auto op = base::Term<base::EngineOp>::create(
        CLEANUP_DECODER_VARIABLES_TRACEABLE_NAME,
        [enabled, isTestMode](base::Event event) -> base::result::Result<base::Event>
        {
            if (!enabled)
            {
                if (isTestMode)
                {
                    return base::result::makeSuccess<decltype(event)>(
                        event, "cleanupDecoderTemporaryVariables() -> Skipped: Cleanup disabled by policy");
                }
                return base::result::makeSuccess<decltype(event)>(event);
            }

            try
            {
                event->eraseRootKeysByPrefix("_");
            }
            catch (const std::exception& e)
            {
                if (isTestMode)
                {
                    return base::result::makeFailure<decltype(event)>(
                        event,
                        fmt::format("cleanupDecoderTemporaryVariables() -> Failure: Could not remove root keys "
                                    "prefixed with '_' ({})",
                                    e.what()));
                }
                return base::result::makeFailure<decltype(event)>(event);
            }

            if (isTestMode)
            {
                return base::result::makeSuccess<decltype(event)>(
                    event, "cleanupDecoderTemporaryVariables() -> Success: Removed root keys prefixed with '_'");
            }
            return base::result::makeSuccess<decltype(event)>(event);
        });

    return std::make_pair(makeTraceableSuccessExpression(op, isTestMode), CLEANUP_DECODER_VARIABLES_TRACEABLE_NAME);
}

base::Expression makeFilterDiscardCounter(const base::Expression& phaseExpr,
                                          const std::shared_ptr<fastmetrics::ICounter>& counter,
                                          const std::string& name)
{
    // Create a term that increments the counter and returns failure
    auto counterTerm =
        base::Term<base::EngineOp>::create(name,
                                           [counter](base::Event event) -> base::result::Result<base::Event>
                                           {
                                               counter->add(1);
                                               return base::result::makeFailure<decltype(event)>(event);
                                           });

    // Wrap: if phaseExpr fails, run counterTerm (which increments and propagates failure)
    // phaseExpr => success path (pass through), failure path => counterTerm
    // We use Or: try phaseExpr first, if it fails try counterTerm
    return base::Or::create(name + "/wrapper", {phaseExpr, counterTerm});
}

} // namespace builder::builders::enrichment

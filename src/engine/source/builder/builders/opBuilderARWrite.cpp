/* Copyright (C) 2015-2022, Wazuh Inc.
 * All rights reserved.
 *
 */

#include "opBuilderARWrite.hpp"

#include <string>

#include <logging/logging.hpp>
#include <utils/socketInterface/unixDatagram.hpp>
#include <utils/stringUtils.hpp>

#include "syntax.hpp"

using base::utils::socketInterface::SendRetval;
using base::utils::socketInterface::unixDatagram;
using builder::internals::syntax::REFERENCE_ANCHOR;
using rapidjson::Value;
using std::runtime_error;
using std::string;
using utils::string::split;

namespace builder::internals::builders
{

base::Lifter opBuilderARWrite(const base::DocumentValue& def, types::TracerFn tr)
{
    // The first parameter should be a string
    if (!def.MemberBegin()->value.IsString())
    {
        throw runtime_error(
            "Write AR operator: Invalid parameter type (string expected).");
    }

    // This is the left side operator, which is set with the operation result.
    const string resultOperatorKey {
        json::formatJsonPath(def.MemberBegin()->name.GetString())};

    // Parse parameters
    const auto parametersArr {split(def.MemberBegin()->value.GetString(), '/')};

    // It is expected to have only two parameters (operation and query)
    if (parametersArr.size() != 2)
    {
        throw runtime_error(
            "Write AR operator: Invalid number of parameters (two expected).");
    }

    // Check for empty parameter
    if (parametersArr.at(1).empty())
    {
        throw runtime_error(
            "Write AR operator: Invalid empty parameters (not empty expected).");
    }

    // Assigned to parameter in order to avoid handling array with 1 value
    const string opParameter = parametersArr.at(1);

    base::Document doc {def};

    // Return Lifter
    return [&, resultOperatorKey, opParameter, tr = std::move(tr)](base::Observable o) {
        return o.map([&, resultOperatorKey, opParameter, tr = std::move(tr)](
                         base::Event e) {
            string query {};
            bool messageSent {false};

            // Check if the value comes from a reference
            if (REFERENCE_ANCHOR == opParameter[0])
            {
                // Gets the referenced key (without the reference anchor)
                const auto key = json::formatJsonPath(opParameter.substr(1));

                try
                {
                    // Gets the value referenced by the key
                    auto value =
                        (opParameter.length() > 1) ? &e->getEventValue(key) : nullptr;

                    if (value && value->IsString())
                    {
                        query = value->GetString();

                        if (query.empty())
                        {
                            const string msg {AR_INVALID_REFERENCE_MSG};
                            tr(msg);
                            WAZUH_LOG_ERROR(msg);
                        }
                    }
                    else
                    {
                        const string msg {AR_INVALID_REFERENCE_MSG};
                        tr(msg);
                        WAZUH_LOG_ERROR(msg);
                    }
                }
                catch (std::exception& exception)
                {
                    const string msg =
                        string {"Write AR operator exception: "} + exception.what();
                    tr(msg);
                    WAZUH_LOG_ERROR(msg);
                }
            }
            else // It is a direct value
            {
                query = opParameter;
            }

            if (!query.empty())
            {
                try
                {
                    unixDatagram socketAR(AR_QUEUE_PATH);

                    if (socketAR.sendMsg(query) == SendRetval::SUCCESS)
                    {
                        messageSent = true;

                        const string msg {
                            "Write AR operator info: AR message sent. Query: " + query};
                        tr(msg);
                        WAZUH_LOG_DEBUG(msg);
                    }
                    else
                    {
                        const string msg {
                            "Write AR operator error: AR message not sent. Document: "
                            + doc.str()};
                        tr(msg);
                        WAZUH_LOG_ERROR(msg);
                    }
                }
                catch (const std::exception& exception)
                {
                    const string msg = string {"Write AR operator sendMsg() exception: "}
                                       + exception.what();
                    tr(msg);
                    WAZUH_LOG_ERROR(msg);
                }
            }

            e->setEventValue(resultOperatorKey, Value(messageSent).Move());

            return e;
        });
    };
}

} // namespace builder::internals::builders

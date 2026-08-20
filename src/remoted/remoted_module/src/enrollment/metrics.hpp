/*
 * Wazuh remoted module - Enrollment endpoint metrics
 * Copyright (C) 2015, Wazuh Inc.
 * August 19, 2026.
 *
 * This program is free software; you can redistribute it
 * and/or modify it under the terms of the GNU General Public
 * License (version 2) as published by the FSF - Free Software
 * Foundation.
 */

#ifndef _REMOTED_ENROLLMENT_METRICS_HPP
#define _REMOTED_ENROLLMENT_METRICS_HPP

#include <memory>

#include <wazuh_metrics/iManager.hpp>

namespace remoted::enrollment
{
    // The remoted.enroll.* name catalog.
    constexpr auto METRIC_ACCEPTED {"remoted.enroll.accepted"};
    constexpr auto METRIC_REJECTED_AUTH {"remoted.enroll.rejected_auth"};
    constexpr auto METRIC_REJECTED_VALIDATION {"remoted.enroll.rejected_validation"};
    constexpr auto METRIC_DISABLED {"remoted.enroll.disabled"};
    constexpr auto METRIC_AUTHD_ERROR {"remoted.enroll.authd_error"};
    constexpr auto METRIC_AUTHD_UNAVAILABLE {"remoted.enroll.authd_unavailable"};

    struct EnrollmentMetrics
    {
        std::shared_ptr<wazuh::metrics::ICounter> accepted;
        std::shared_ptr<wazuh::metrics::ICounter> rejectedAuth;
        std::shared_ptr<wazuh::metrics::ICounter> rejectedValidation;
        std::shared_ptr<wazuh::metrics::ICounter> disabled;
        std::shared_ptr<wazuh::metrics::ICounter> authdError;
        std::shared_ptr<wazuh::metrics::ICounter> authdUnavailable;
    };

    inline EnrollmentMetrics makeEnrollmentMetrics(wazuh::metrics::IManager& manager)
    {
        return EnrollmentMetrics {
            manager.getOrCreateCounter(METRIC_ACCEPTED, "Enrollment requests that succeeded", "count"),
            manager.getOrCreateCounter(METRIC_REJECTED_AUTH, "Enrollment requests rejected on authentication", "count"),
            manager.getOrCreateCounter(
                METRIC_REJECTED_VALIDATION,
                "Enrollment requests rejected on local validation (Content-Encoding/schema/version)",
                "count"),
            manager.getOrCreateCounter(METRIC_DISABLED,
                                       "Enrollment requests rejected because enrollment is administratively disabled",
                                       "count"),
            manager.getOrCreateCounter(
                METRIC_AUTHD_ERROR, "Enrollment requests rejected by authd's own business rules", "count"),
            manager.getOrCreateCounter(
                METRIC_AUTHD_UNAVAILABLE, "Enrollment requests that got no clean answer from authd", "count")};
    }

    inline void incAccepted(EnrollmentMetrics& m)
    {
        if (m.accepted)
        {
            m.accepted->add();
        }
    }

    inline void incRejectedAuth(EnrollmentMetrics& m)
    {
        if (m.rejectedAuth)
        {
            m.rejectedAuth->add();
        }
    }

    inline void incRejectedValidation(EnrollmentMetrics& m)
    {
        if (m.rejectedValidation)
        {
            m.rejectedValidation->add();
        }
    }

    inline void incDisabled(EnrollmentMetrics& m)
    {
        if (m.disabled)
        {
            m.disabled->add();
        }
    }

    inline void incAuthdError(EnrollmentMetrics& m)
    {
        if (m.authdError)
        {
            m.authdError->add();
        }
    }

    inline void incAuthdUnavailable(EnrollmentMetrics& m)
    {
        if (m.authdUnavailable)
        {
            m.authdUnavailable->add();
        }
    }

} // namespace remoted::enrollment

#endif // _REMOTED_ENROLLMENT_METRICS_HPP

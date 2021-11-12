// -------------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License (MIT). See LICENSE in the repo root for license information.
// -------------------------------------------------------------------------------------------------

using System;
using System.Collections.Generic;
using EnsureThat;
using Microsoft.Health.Common.Telemetry;
using Microsoft.Health.Logging.Telemetry;

namespace Microsoft.Health.Extensions.Fhir.Telemetry.Exceptions
{
    public class FhirServiceExceptionTelemetryProcessor
    {
        private readonly ISet<Type> _handledExceptions;

        public FhirServiceExceptionTelemetryProcessor()
            : this(
                typeof(InvalidFhirServiceException),
                typeof(UnauthorizedAccessFhirServiceException))
        {
        }

        public FhirServiceExceptionTelemetryProcessor(params Type[] handledExceptionTypes)
        {
            _handledExceptions = new HashSet<Type>(handledExceptionTypes);
        }

        public void LogExceptionAndMetric(Exception ex, ITelemetryLogger logger)
        {
            EnsureArg.IsNotNull(ex, nameof(ex));
            EnsureArg.IsNotNull(logger, nameof(logger));

            logger.LogError(ex);

            var exType = ex.GetType();
            var lookupType = exType.IsGenericType ? exType.GetGenericTypeDefinition() : exType;

            if (_handledExceptions.Contains(lookupType))
            {
                if (ex is ITelemetryFormattable tel)
                {
                    logger.LogMetric(
                        metric: tel.ToMetric,
                        metricValue: 1);
                }
            }
        }
    }
}

﻿// -------------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License (MIT). See LICENSE in the repo root for license information.
// -------------------------------------------------------------------------------------------------

using Microsoft.Health.Common.Telemetry;

namespace Microsoft.Health.Extensions.Fhir.Telemetry.Metrics
{
    public class FhirClientMetrics
    {
        /// <summary>
        /// A metric recorded when there is an error reading from or connecting with a FHIR server.
        /// </summary>
        /// <param name="exceptionName">The name of the exception</param>
        /// <param name="severity">The severity of the error</param>
        /// <param name="connectorStage">The stage of the connector</param>
        public static Metric HandledException(string exceptionName, string severity, string connectorStage)
        {
            return exceptionName.ToErrorMetric(connectorStage, ErrorType.GeneralError, severity);
        }
    }
}

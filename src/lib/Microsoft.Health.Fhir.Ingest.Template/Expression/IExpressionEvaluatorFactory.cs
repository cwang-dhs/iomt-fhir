// -------------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License (MIT). See LICENSE in the repo root for license information.
// -------------------------------------------------------------------------------------------------

namespace Microsoft.Health.Fhir.Ingest.Template.Expression
{
    public interface IExpressionEvaluatorFactory
    {
        IExpressionEvaluator Create(Expression expression);
    }
}
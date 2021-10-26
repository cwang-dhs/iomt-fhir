﻿// -------------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License (MIT). See LICENSE in the repo root for license information.
// -------------------------------------------------------------------------------------------------

using System.Collections.Generic;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;
using EnsureThat;
using Hl7.Fhir.Model;
using Hl7.Fhir.Rest;
using Microsoft.Health.Common;

namespace Microsoft.Health.Extensions.Fhir.Repository
{
    public class FhirServerRepository : IFhirServerRepository
    {
        private readonly IFactory<BaseFhirClient> _fhirClientFactory;

        public FhirServerRepository(IFactory<BaseFhirClient> fhirClientFactory)
        {
            _fhirClientFactory = EnsureArg.IsNotNull(fhirClientFactory, nameof(fhirClientFactory));
        }

        public async Task<T> CreateResourceAsync<T>(T resource, CancellationToken cancellationToken = default)
            where T : Resource
        {
            using (var client = _fhirClientFactory.Create())
            {
                return await client.CreateAsync(resource);
            }
        }

        public async Task<Bundle> SearchForResourceAsync<T>(SearchParams searchParams, CancellationToken cancellationToken = default)
            where T : Resource
        {
            using (var client = _fhirClientFactory.Create())
            {
                return await client.SearchAsync<T>(searchParams);
            }
        }

        public async Task<T> UpdateResourceAsync<T>(T resource, bool versionAware, CancellationToken cancellationToken = default)
            where T : Resource
        {
            using (var client = _fhirClientFactory.Create())
            {
                return await client.UpdateAsync(resource);
            }
        }

        public async IAsyncEnumerable<Bundle> IterateOverAdditionalBundlesAsync(Bundle bundle, PageDirection pageDirection = PageDirection.Next, [EnumeratorCancellation]CancellationToken cancellationToken = default)
        {
            using (var client = _fhirClientFactory.Create())
            {
                Bundle trackedBundle = bundle;
                while (trackedBundle != null)
                {
                    trackedBundle = await client.ContinueAsync(trackedBundle).ConfigureAwait(false);
                    if (trackedBundle != null)
                    {
                        yield return trackedBundle;
                    }
                }
            }
        }
    }
}
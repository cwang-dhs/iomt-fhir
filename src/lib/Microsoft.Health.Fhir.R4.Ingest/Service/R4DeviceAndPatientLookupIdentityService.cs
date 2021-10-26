﻿// -------------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License (MIT). See LICENSE in the repo root for license information.
// -------------------------------------------------------------------------------------------------

using System.Threading.Tasks;
using EnsureThat;
using Microsoft.Health.Extensions.Fhir;
using Microsoft.Health.Extensions.Fhir.Service;
using Microsoft.Health.Fhir.Ingest.Config;
using Microsoft.Health.Fhir.Ingest.Data;
using Microsoft.Health.Fhir.Ingest.Host;
using Model = Hl7.Fhir.Model;

namespace Microsoft.Health.Fhir.Ingest.Service
{
    [ResourceIdentityService(ResourceIdentityServiceType.Lookup)]
    [ResourceIdentityService(nameof(R4DeviceAndPatientLookupIdentityService))]
    public class R4DeviceAndPatientLookupIdentityService : DeviceAndPatientLookupIdentityService
    {
        public R4DeviceAndPatientLookupIdentityService(
            ResourceManagementService resourceManagementService,
            ResourceIdentityServiceType serviceType = ResourceIdentityServiceType.Lookup)
            : base(serviceType)
        {
            ResourceManagementService = EnsureArg.IsNotNull(resourceManagementService, nameof(resourceManagementService));
        }

        protected ResourceManagementService ResourceManagementService { get; private set; }

        public ResourceIdentityServiceType ResourceIdentityServiceType { get; } = ResourceIdentityServiceType.Lookup;

        protected static string GetPatientIdFromDevice(Model.Device device)
        {
            EnsureArg.IsNotNull(device, nameof(device));

            return device.Patient?.GetId<Model.Patient>() ?? throw new FhirResourceNotFoundException(ResourceType.Patient);
        }

        protected async override Task<(string DeviceId, string PatientId)> LookUpDeviceAndPatientIdAsync(string value, string system = null)
        {
            var device = await ResourceManagementService.GetResourceByIdentityAsync<Model.Device>(value, system).ConfigureAwait(false) ?? throw new FhirResourceNotFoundException(ResourceType.Device);
            return (device.Id, GetPatientIdFromDevice(device));
        }
    }
}

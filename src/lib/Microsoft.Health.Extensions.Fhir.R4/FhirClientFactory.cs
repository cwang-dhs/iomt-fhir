// -------------------------------------------------------------------------------------------------
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License (MIT). See LICENSE in the repo root for license information.
// -------------------------------------------------------------------------------------------------

using System;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Threading;
using System.Threading.Tasks;
using Azure.Core;
using EnsureThat;
using Hl7.Fhir.Rest;
using Microsoft.Extensions.Options;
using Microsoft.Health.Common;
using Microsoft.Health.Common.Auth;
using Microsoft.Health.Common.Telemetry;
using Microsoft.Health.Extensions.Fhir.Config;
using Microsoft.Health.Extensions.Fhir.Telemetry.Exceptions;
using Microsoft.Health.Extensions.Fhir.Telemetry.Metrics;
using Microsoft.Health.Extensions.Host.Auth;
using Microsoft.Health.Logging.Telemetry;

namespace Microsoft.Health.Extensions.Fhir
{
    public class FhirClientFactory : IFactory<FhirClient>
    {
        private readonly bool _useManagedIdentity = false;
        private readonly IAzureCredentialProvider _tokenCredentialProvider;
        private readonly ITelemetryLogger _logger;
        private static readonly FhirServiceExceptionTelemetryProcessor _exceptionTelemetryProcessor = new FhirServiceExceptionTelemetryProcessor();
        private static readonly string _errorType = ErrorType.FHIRServerError;

        public FhirClientFactory(IOptions<FhirClientFactoryOptions> options, ITelemetryLogger logger)
            : this(EnsureArg.IsNotNull(options, nameof(options)).Value.UseManagedIdentity, logger)
        {
        }

        private FhirClientFactory()
            : this(useManagedIdentity: false, logger: null)
        {
        }

        private FhirClientFactory(bool useManagedIdentity, ITelemetryLogger logger)
        {
            _useManagedIdentity = useManagedIdentity;
            _logger = logger;
        }

        public FhirClientFactory(IAzureCredentialProvider provider, ITelemetryLogger logger)
        {
            _tokenCredentialProvider = provider;
            _logger = logger;
        }

        public static IFactory<FhirClient> Instance { get; } = new FhirClientFactory();

        public FhirClient Create()
        {
            if (_tokenCredentialProvider != null)
            {
                return CreateClient(_tokenCredentialProvider.GetCredential(), _logger);
            }

            return _useManagedIdentity ? CreateManagedIdentityClient(_logger) : CreateConfidentialApplicationClient(_logger);
        }

        private static FhirClient CreateClient(TokenCredential tokenCredential, ITelemetryLogger logger)
        {
            var url = Environment.GetEnvironmentVariable("FhirService:Url");
            EnsureArg.IsNotNullOrEmpty(url, nameof(url));
            ValidateFhirServiceUrl(url, logger);

            var uri = new Uri(url);

            EnsureArg.IsNotNull(tokenCredential, nameof(tokenCredential));

            var fhirClientSettings = new FhirClientSettings
            {
                PreferredFormat = ResourceFormat.Json,
            };

            var client = new FhirClient(url, fhirClientSettings, new BearerTokenAuthorizationMessageHandler(uri, tokenCredential, logger));
            ValidateFhirService(client, logger);

            return client;
        }

        private static FhirClient CreateManagedIdentityClient(ITelemetryLogger logger)
        {
            return CreateClient(new ManagedIdentityAuthService(), logger);
        }

        private static FhirClient CreateConfidentialApplicationClient(ITelemetryLogger logger)
        {
            return CreateClient(new OAuthConfidentialClientAuthService(), logger);
        }

        private static void ValidateFhirServiceUrl(string url, ITelemetryLogger logger)
        {
            using (HttpClient client = new HttpClient())
            {
                try
                {
                    var response = client.GetAsync(url).Result;

                    if (!response.IsSuccessStatusCode)
                    {
                        var statusCode = response.StatusCode;
                        string message;
                        Exception customEx;

                        switch (statusCode)
                        {
                            case HttpStatusCode.NotFound:
                                message = "Verify that the provided FHIR service URL is the Service Base URL and does not contain any resources.";
                                customEx = new InvalidFhirServiceException(message, nameof(FhirServiceErrorCode.ConfigurationError));
                                break;
                            case HttpStatusCode.Unauthorized:
                                message = "Verify that the provided FHIR service's 'FHIR Data Writer' role has been assigned to the applicable Azure Active Directory security principal or managed identity.";
                                customEx = new UnauthorizedAccessFhirServiceException(message, nameof(FhirServiceErrorCode.AuthorizationError));
                                break;
                            default:
                                logger.LogMetric(FhirClientMetrics.HandledException($"{_errorType}{statusCode}", ErrorSeverity.Critical), 1);
                                return;
                        }

                        _exceptionTelemetryProcessor.LogExceptionAndMetric(customEx, logger);
                    }
                }
                catch (Exception ex)
                {
                    Exception e = ex is AggregateException ? ex.InnerException : ex;
                    string message;

                    switch (e)
                    {
                        case InvalidOperationException _:
                            message = "Verify that the provided FHIR service URL is an absolute URL.";
                            break;
                        case HttpRequestException _:
                            message = "Verify that the provided FHIR service URL exists.";
                            break;
                        default:
                            string errorName = e != null ? e.GetType().Name : string.Empty;
                            logger.LogMetric(FhirClientMetrics.HandledException($"{_errorType}{errorName}", ErrorSeverity.Critical), 1);
                            return;
                    }

                    var customEx = new InvalidFhirServiceException(message, e, nameof(FhirServiceErrorCode.ConfigurationError));
                    _exceptionTelemetryProcessor.LogExceptionAndMetric(customEx, logger);
                }
            }
        }

        private static void ValidateFhirService(FhirClient fhirClient, ITelemetryLogger logger)
        {
            try
            {
                var capabilityStatement = fhirClient.CapabilityStatement(SummaryType.Count);
                if (capabilityStatement == null || capabilityStatement.FhirVersion == null)
                {
                    logger.LogMetric(FhirClientMetrics.HandledException($"{_errorType}", ErrorSeverity.Critical), 1);
                }
            }
            catch (Exception ex)
            {
                var message = "Verify that the provided URL is for the FHIR service.";
                var customEx = new InvalidFhirServiceException(message, ex, nameof(FhirServiceErrorCode.ConfigurationError));
                _exceptionTelemetryProcessor.LogExceptionAndMetric(customEx, logger);
            }
        }

        private class BearerTokenAuthorizationMessageHandler : HttpClientHandler
        {
            public BearerTokenAuthorizationMessageHandler(Uri uri, TokenCredential tokenCredentialProvider, ITelemetryLogger logger)
            {
                TokenCredential = EnsureArg.IsNotNull(tokenCredentialProvider, nameof(tokenCredentialProvider));
                Uri = EnsureArg.IsNotNull(uri);
                Scopes = new string[] { Uri + ".default" };
                Logger = logger;
            }

            private ITelemetryLogger Logger { get; }

            private TokenCredential TokenCredential { get; }

            private Uri Uri { get; }

            private string[] Scopes { get; }

            protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
            {
                var requestContext = new TokenRequestContext(Scopes);
                var accessToken = await TokenCredential.GetTokenAsync(requestContext, CancellationToken.None);
                request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", accessToken.Token);
                var response = await base.SendAsync(request, cancellationToken);

                if (Logger != null && !response.IsSuccessStatusCode)
                {
                    var statusDescription = response.ReasonPhrase.Replace(" ", string.Empty);

                    if (response.StatusCode == HttpStatusCode.TooManyRequests)
                    {
                        Logger.LogMetric(FhirClientMetrics.HandledException($"{_errorType}{statusDescription}", ErrorSeverity.Informational), 1);
                    }
                    else
                    {
                        Logger.LogMetric(FhirClientMetrics.HandledException($"{_errorType}{statusDescription}", ErrorSeverity.Critical), 1);
                    }
                }

                return response;
            }
        }
    }
}

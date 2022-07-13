using System.Diagnostics;
using System.Runtime.CompilerServices;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Matching;

namespace AspNetCore.Authorization.PathBased;

internal class EndpointMetadataDecoratorMatcherPolicy : MatcherPolicy, IEndpointSelectorPolicy
{
    private readonly ConditionalWeakTable<Endpoint, Endpoint> _endpointsCache = new();

    public override int Order { get; }

    public bool AppliesToEndpoints(IReadOnlyList<Endpoint> endpoints)
    {
        return endpoints.Any(e => MetadataOnlyEndpoint.IsMetadataOnlyEndpoint(e)
            && e.Metadata.GetMetadata<MetadataOnlyEndpointMetadata>() is not null);
    }

    public Task ApplyAsync(HttpContext httpContext, CandidateSet candidates)
    {
        // Try to find cache entry for single candidate
        var firstCandidate = candidates[0];
        Endpoint? cachedEndpoint;
        if (candidates.Count == 1 && _endpointsCache.TryGetValue(firstCandidate.Endpoint, out cachedEndpoint))
        {
            // Only use the current request's route values if the candidate match is an actual endpoint
            var values = !MetadataOnlyEndpoint.IsMetadataOnlyEndpoint(firstCandidate.Endpoint)
                ? firstCandidate.Values
                : null;
            candidates.ReplaceEndpoint(0, cachedEndpoint, values);
            return Task.CompletedTask;
        }

        // Fallback to looping through all candiates
        Endpoint? firstMetadataOnlyEndpoint = null;
        // PERF: Use a list type optimized for small item counts instead
        List<Endpoint>? metadataOnlyEndpoints = null;
        var replacementCandidateIndex = -1;
        var realEndpointCandidateCount = 0;

        for (int i = 0; i < candidates.Count; i++)
        {
            var candidate = candidates[i];

            if (MetadataOnlyEndpoint.IsMetadataOnlyEndpoint(candidate.Endpoint))
            {
                if (firstMetadataOnlyEndpoint is null)
                {
                    firstMetadataOnlyEndpoint = candidate.Endpoint;
                }
                else
                {
                    if (metadataOnlyEndpoints is null)
                    {
                        metadataOnlyEndpoints = new List<Endpoint>();
                        metadataOnlyEndpoints.Add(firstMetadataOnlyEndpoint);
                    }
                    metadataOnlyEndpoints.Add(candidate.Endpoint);
                }
                if (realEndpointCandidateCount == 0 && replacementCandidateIndex == -1)
                {
                    // Only capture index of first metadata only endpoint as candidate replacement
                    replacementCandidateIndex = i;
                }
            }
            else
            {
                realEndpointCandidateCount++;
                if (realEndpointCandidateCount == 1)
                {
                    // Only first real endpoint is a candidate
                    replacementCandidateIndex = i;
                }
            }
        }

        Debug.Assert(firstMetadataOnlyEndpoint is not null);
        Debug.Assert(metadataOnlyEndpoints?.Count >= 1 || firstMetadataOnlyEndpoint is not null);
        Debug.Assert(replacementCandidateIndex >= 0);

        var activeCandidate = candidates[replacementCandidateIndex];
        var activeEndpoint = (RouteEndpoint)activeCandidate.Endpoint;

        // TODO: Review what the correct behavior is if there is more than 1 real endpoint candidate.

        if (realEndpointCandidateCount is 0 or 1 && activeEndpoint is not null)
        {
            Endpoint? replacementEndpoint = null;

            // Check cache for replacement endpoint
            if (!_endpointsCache.TryGetValue(activeEndpoint, out replacementEndpoint))
            {
                // Not found in cache so build up the replacement endpoint
                IReadOnlyList<object> decoratedMetadata = metadataOnlyEndpoints is not null
                    ? metadataOnlyEndpoints.SelectMany(e => e.Metadata).ToList()
                    : firstMetadataOnlyEndpoint.Metadata;

                if (realEndpointCandidateCount == 1)
                {
                    var routeEndpointBuilder = new RouteEndpointBuilder(activeEndpoint.RequestDelegate!, activeEndpoint.RoutePattern, activeEndpoint.Order);

                    routeEndpointBuilder.DisplayName = activeEndpoint.DisplayName;

                    // Add metadata from metadata-only endpoint candidates
                    foreach (var metadata in decoratedMetadata)
                    {
                        routeEndpointBuilder.Metadata.Add(metadata);
                    }

                    // Add metadata from active endpoint
                    if (realEndpointCandidateCount > 0)
                    {
                        foreach (var metadata in activeEndpoint.Metadata)
                        {
                            if (metadata is not null)
                            {
                                routeEndpointBuilder.Metadata.Add(metadata);
                            }
                        }
                    }

                    replacementEndpoint = routeEndpointBuilder.Build();
                }
                else
                {
                    replacementEndpoint = new MetadataOnlyEndpoint(activeEndpoint, decoratedMetadata);
                }

                _endpointsCache.Add(activeEndpoint, replacementEndpoint);
            }
            var values = realEndpointCandidateCount == 1 ? activeCandidate.Values : null;

            // Replace the endpoint
            candidates.ReplaceEndpoint(replacementCandidateIndex, replacementEndpoint, values);
        }

        return Task.CompletedTask;
    }
}

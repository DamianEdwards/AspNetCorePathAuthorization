using System.Diagnostics;
using System.Runtime.CompilerServices;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Matching;

namespace AspNetCore.Authorization.PathBased;

internal class EndpointMetadataDecoratorMatcherPolicy : MatcherPolicy, IEndpointSelectorPolicy
{
    private readonly ConditionalWeakTable<Endpoint, Endpoint> _endpointsCache = new();

    internal static readonly RequestDelegate NoOpRequestDelegate = (ctx) => Task.CompletedTask;

    public override int Order { get; }

    public bool AppliesToEndpoints(IReadOnlyList<Endpoint> endpoints)
    {
        return endpoints.Any(e => ReferenceEquals(e.RequestDelegate, NoOpRequestDelegate)
            && e.Metadata.GetMetadata<MetadataOnlyEndpointMetadata>() != null);
    }

    public Task ApplyAsync(HttpContext httpContext, CandidateSet candidates)
    {
        // Try to retrieve decorated endpoint from cache
        for (int i = 0; i < candidates.Count; i++)
        {
            var candidate = candidates[i];
            if (_endpointsCache.TryGetValue(candidate.Endpoint, out var cachedEndpoint))
            {
                // Only use the current request's route values if the candidate match is an actual endpoint
                var values = !ReferenceEquals(candidate.Endpoint.RequestDelegate, NoOpRequestDelegate)
                    ? candidate.Values
                    : null;
                candidates.ReplaceEndpoint(i, cachedEndpoint, values);
                return Task.CompletedTask;
            }
        }

        // Not found in cache so build up the replacement endpoint
        List<Endpoint>? metadataOnlyEndpoints = null;
        CandidateState actualCandidate = default;
        var replacementCandidateIndex = -1;
        var actualCandidateCount = 0;

        for (int i = 0; i < candidates.Count; i++)
        {
            var candidate = candidates[i];

            if (ReferenceEquals(candidate.Endpoint.RequestDelegate, NoOpRequestDelegate))
            {
                metadataOnlyEndpoints ??= new();
                metadataOnlyEndpoints.Add(candidate.Endpoint);
                if (actualCandidateCount == 0)
                {
                    replacementCandidateIndex = i;

                    // TODO: Review necessisty of setting candidate validity (doesn't seem to matter?)
                    //if (i < (candidates.Count - 1))
                    //{
                    //    candidates.SetValidity(i, false);
                    //}
                }
            }
            else
            {
                actualCandidate = candidate;
                replacementCandidateIndex = i;
                actualCandidateCount++;
            }
        }

        Debug.Assert(metadataOnlyEndpoints?.Count >= 1);
        Debug.Assert(replacementCandidateIndex >= 0);

        var activeEndpoint = actualCandidateCount switch
        {
            1 => (RouteEndpoint)actualCandidate.Endpoint,
            0 => (RouteEndpoint)candidates[replacementCandidateIndex].Endpoint,
            _ => null
        };

        // TODO: Review what the correct behavior is if there is more than 1 actual candidate

        if (activeEndpoint is not null)
        {
            Endpoint? replacementEndpoint = null;

            var decoratedMetadata = metadataOnlyEndpoints.SelectMany(e => e.Metadata).ToList();

            if (actualCandidateCount == 1)
            {
                var routeEndpointBuilder = new RouteEndpointBuilder(activeEndpoint.RequestDelegate!, activeEndpoint.RoutePattern, activeEndpoint.Order);

                // Add metadata from metadata-only endpoint candidates
                foreach (var metadata in decoratedMetadata)
                {
                    routeEndpointBuilder.Metadata.Add(metadata);
                }

                // Add metadata from actual candidate endpoint
                foreach (var metadata in actualCandidate.Endpoint.Metadata)
                {
                    if (metadata is not null)
                    {
                        routeEndpointBuilder.Metadata.Add(metadata);
                    }
                }

                replacementEndpoint = routeEndpointBuilder.Build();
            }
            else
            {
                replacementEndpoint = new MetadataOnlyEndpoint(activeEndpoint, decoratedMetadata);
            }

            _endpointsCache.Add(activeEndpoint, replacementEndpoint);

            var values = actualCandidateCount == 1 ? actualCandidate.Values : null;

            candidates.ReplaceEndpoint(replacementCandidateIndex, replacementEndpoint, values);
            //candidates.SetValidity(replacementCandidateIndex, true);
        }

        return Task.CompletedTask;
    }
}

internal class MetadataOnlyEndpointMetadata
{

}

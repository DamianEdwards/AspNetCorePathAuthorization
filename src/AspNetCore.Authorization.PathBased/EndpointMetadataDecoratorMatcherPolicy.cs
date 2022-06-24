using System.Diagnostics;
using System.Runtime.CompilerServices;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Routing.Matching;

namespace AspNetCore.Authorization.PathBased;

internal class EndpointMetadataDecoratorMatcherPolicy : MatcherPolicy, IEndpointSelectorPolicy
{
    private readonly ConditionalWeakTable<Endpoint, Endpoint> _endpointsCache = new();

    public override int Order { get; } = 0;

    public bool AppliesToEndpoints(IReadOnlyList<Endpoint> endpoints)
    {
        return endpoints.Any(e => e.Metadata.GetMetadata<MatcherPolicyMetadata>() != null);
    }

    public Task ApplyAsync(HttpContext httpContext, CandidateSet candidates)
    {
        if (candidates.Count == 1)
        {
            return Task.CompletedTask;
        }

        // Try to retrieve decorated endpoint from cache
        for (int i = 0; i < candidates.Count; i++)
        {
            var candidate = candidates[i];
            if (_endpointsCache.TryGetValue(candidate.Endpoint, out var cachedEndpoint))
            {
                candidates.ReplaceEndpoint(i, cachedEndpoint, candidate.Values);
                return Task.CompletedTask;
            }
        }

        // Not found in cache so build up the decorated endpoint
        var policyEndpoints = new List<Endpoint>(candidates.Count);
        CandidateState actualCandidate = default;
        var replacementCandidateIndex = -1;
        var actualCandidateCount = 0;

        for (int i = 0; i < candidates.Count; i++)
        {
            var candidate = candidates[i];

            if (candidate.Endpoint.Metadata.GetMetadata<MatcherPolicyMetadata>() != null)
            {
                candidates.SetValidity(i, false);
                policyEndpoints.Add(candidate.Endpoint);
                if (actualCandidateCount == 0)
                {
                    replacementCandidateIndex = i;
                }
            }
            else
            {
                actualCandidate = candidate;
                replacementCandidateIndex = i;
                actualCandidateCount++;
            }
        }

        Debug.Assert(policyEndpoints.Count >= 1);
        Debug.Assert(replacementCandidateIndex >= 0);

        var activeEndpoint = actualCandidateCount switch
        {
            1 => (RouteEndpoint)actualCandidate.Endpoint,
            0 => (RouteEndpoint)candidates[replacementCandidateIndex].Endpoint,
            _ => null
        };

        if (activeEndpoint is not null)
        {
            var newEndpoint = new RouteEndpointBuilder(activeEndpoint.RequestDelegate!, activeEndpoint.RoutePattern, activeEndpoint.Order);

            foreach (var endpoint in policyEndpoints)
            {
                foreach (var metadata in endpoint.Metadata)
                {
                    if (metadata is not null)
                    {
                        newEndpoint.Metadata.Add(metadata);
                    }
                }
            }

            if (actualCandidateCount == 1)
            {
                foreach (var metadata in activeEndpoint.Metadata)
                {
                    if (metadata is not null)
                    {
                        newEndpoint.Metadata.Add(metadata);
                    }
                }
            }

            var replacementEndpoint = newEndpoint.Build();
            _endpointsCache.Add(activeEndpoint, replacementEndpoint);

            var values = actualCandidateCount == 1 ? actualCandidate.Values : null;
            candidates.ReplaceEndpoint(replacementCandidateIndex, replacementEndpoint, values);
            candidates.SetValidity(replacementCandidateIndex, true);
        }

        return Task.CompletedTask;
    }
}

internal class MatcherPolicyMetadata
{

}

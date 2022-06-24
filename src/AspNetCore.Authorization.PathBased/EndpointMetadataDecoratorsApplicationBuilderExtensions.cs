using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using AspNetCore.Authorization.PathBased;

namespace Microsoft.AspNetCore.Builder;

public static class EndpointMetadataDecoratorsApplicationBuilderExtensions
{
    /// <summary>
    /// Adds a <see cref="RouteEndpoint"/> to the <see cref="IEndpointRouteBuilder"/> that adds the provided metadata items to
    /// any <see cref="RouteEndpoint"/> mapped to HTTP requests for the specified pattern.
    /// </summary>
    /// <typeparam name="T">The specific <see cref="IEndpointRouteBuilder"/> type.</typeparam>
    /// <param name="endpoints">The <typeparamref name="T"/> builder.</param>
    /// <param name="pattern">The route pattern.</param>
    /// <param name="items">A collection of metadata items.</param>
    /// <returns>An <see cref="IEndpointConventionBuilder"/> that can be used to further customize the endpoint.</returns>
    public static IEndpointConventionBuilder MapMetadata<T>(this T endpoints, string pattern, params object[] items)
        where T : IEndpointRouteBuilder
    {
        var _ = endpoints.ServiceProvider.GetRequiredService<MatcherPolicyMetadata>();

        return endpoints.Map(pattern, (ctx) => { return Task.CompletedTask; })
            .WithMetadata(new MatcherPolicyMetadata())
            .WithMetadata(items);
    }
}

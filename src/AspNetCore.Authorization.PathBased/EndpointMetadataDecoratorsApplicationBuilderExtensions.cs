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
    /// <remarks>
    /// Requires <see cref="EndpointMetadataDecoratorServiceCollectionExtensions.AddEndpointMetadataDecorators(IServiceCollection)"/> to have been called.
    /// </remarks>
    /// <typeparam name="T">The specific <see cref="IEndpointRouteBuilder"/> type.</typeparam>
    /// <param name="endpoints">The <typeparamref name="T"/> builder.</param>
    /// <param name="pattern">The route pattern.</param>
    /// <param name="items">A collection of metadata items.</param>
    /// <returns>An <see cref="IEndpointConventionBuilder"/> that can be used to further customize the endpoint.</returns>
    public static IEndpointConventionBuilder MapMetadata<T>(this T endpoints, string pattern, params object[] items)
        where T : IEndpointRouteBuilder
    {
        var servicesAdded = endpoints.ServiceProvider.GetService<MetadataOnlyEndpointMetadata>() is not null;

        if (!servicesAdded)
        {
            throw new InvalidOperationException("Services required for endpoint metadata decorators have not been registered. " +
                                                "Make sure IServiceCollection.AddEndpointMetadataDecorators() was called during app startup.");
        }

        return endpoints.Map(pattern, EndpointMetadataDecoratorMatcherPolicy.NoOpRequestDelegate)
            .WithMetadata(new MetadataOnlyEndpointMetadata())
            .WithMetadata(items);
    }
}

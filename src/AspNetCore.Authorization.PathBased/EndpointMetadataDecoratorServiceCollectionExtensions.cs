using AspNetCore.Authorization.PathBased;
using Microsoft.AspNetCore.Routing;

namespace Microsoft.Extensions.DependencyInjection;

public static class EndpointMetadataDecoratorServiceCollectionExtensions
{
    /// <summary>
    /// Add services to enable endpoint metadata decorators.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/>.</param>
    /// <returns>The <see cref="IServiceCollection"/>.</returns>
    public static IServiceCollection AddEndpointMetadataDecorators(this IServiceCollection services)
    {
        // Add metadata so we can track if this method has been called
        services.AddSingleton<MatcherPolicyMetadata>();

        return services.AddSingleton<MatcherPolicy, EndpointMetadataDecoratorMatcherPolicy>();
    }
}

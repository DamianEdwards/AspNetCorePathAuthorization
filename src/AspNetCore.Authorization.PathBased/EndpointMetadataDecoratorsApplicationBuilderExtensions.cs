using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using AspNetCore.Authorization.PathBased;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing.Patterns;

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

        //endpoints.Map(pattern, (ctx) => Task.CompletedTask);

        var dataSource = endpoints.DataSources.OfType<MetadataOnlyEndpointDataSource>().FirstOrDefault();
        if (dataSource == null)
        {
            dataSource = new MetadataOnlyEndpointDataSource();
            endpoints.DataSources.Add(dataSource);
        }

        var routePattern = RoutePatternFactory.Parse(pattern);
        var endpointBuilder = new MetadataOnlyEndpointBuilder(routePattern, 0);

        foreach(var item in items)
        {
            endpointBuilder.Metadata.Add(item);
        }

        dataSource.AddEndpoint(endpointBuilder);

        return endpointBuilder;
    }
}

internal class MetadataOnlyEndpointBuilder : EndpointBuilder, IEndpointConventionBuilder
{
    public MetadataOnlyEndpointBuilder(RoutePattern routePattern, int order)
    {
        RoutePattern = routePattern;
        Order = order;
        Metadata.Add(new MatcherPolicyMetadata());
        Metadata.Add(new HttpMethodMetadata(Enumerable.Empty<string>()));
    }

    public int Order { get; set; }

    public RoutePattern RoutePattern { get; set; }

    public void Add(Action<EndpointBuilder> convention)
    {
        convention(this);
    }

    public override MetadataOnlyEndpoint Build()
    {
        if (RoutePattern is null)
        {
            throw new InvalidOperationException($"{nameof(RoutePattern)} must be specified to construct a {nameof(MetadataOnlyEndpoint)}.");
        }

        DisplayName = RoutePattern.RawText;

        var endpoint = new MetadataOnlyEndpoint(RoutePattern, new(Metadata), DisplayName);

        return endpoint;
    }

    public override string? ToString() => DisplayName ?? base.ToString();
}

internal class MetadataOnlyEndpoint : Endpoint
{
    private readonly static RequestDelegate? _requestDelegate = (ctx) => Task.CompletedTask;

    public MetadataOnlyEndpoint(
        RoutePattern routePattern,
        EndpointMetadataCollection? metadata,
        string? displayName) : base(_requestDelegate, metadata, displayName)
    {
        RoutePattern = routePattern;
    }

    public int Order { get; }

    public RoutePattern RoutePattern { get; }
}

using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.FileProviders;
using Microsoft.Extensions.Primitives;

namespace AspNetCore.Authorization.PathBased;

internal class MetadataOnlyEndpointDataSource : EndpointDataSource
{
    private readonly List<MetadataOnlyEndpointBuilder> _builders = new();

    public override IReadOnlyList<Endpoint> Endpoints => _builders.Select(b => b.Build()).ToList();

    public override IChangeToken GetChangeToken() => NullChangeToken.Singleton;

    public void AddEndpoint(MetadataOnlyEndpointBuilder endpointBuilder)
    {
        _builders.Add(endpointBuilder);
    }
}

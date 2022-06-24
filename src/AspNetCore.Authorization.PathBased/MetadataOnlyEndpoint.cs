using Microsoft.AspNetCore.Http;

namespace AspNetCore.Authorization.PathBased;

internal class MetadataOnlyEndpoint : Endpoint
{
    public MetadataOnlyEndpoint(Endpoint endpoint)
        : base(null, endpoint.Metadata, endpoint.DisplayName)
    {

    }

    public MetadataOnlyEndpoint(Endpoint endpoint, IList<object> metadata)
        : base(null, new(endpoint.Metadata.Union(metadata)), endpoint.DisplayName)
    {

    }
}

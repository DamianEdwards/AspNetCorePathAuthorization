using Microsoft.AspNetCore.Http;

namespace AspNetCore.Authorization.PathBased;

internal class MetadataOnlyEndpoint : Endpoint
{
    public static readonly RequestDelegate NoOpRequestDelegate = (ctx) => Task.CompletedTask;

    public MetadataOnlyEndpoint(Endpoint endpoint)
        : base(null, endpoint.Metadata, GetDisplayName(endpoint))
    {

    }

    public MetadataOnlyEndpoint(Endpoint endpoint, IList<object> metadata)
        : base(null, new(endpoint.Metadata.Union(metadata)), GetDisplayName(endpoint))
    {

    }

    public static bool IsMetadataOnlyEndpoint(Endpoint endpoint) =>
        ReferenceEquals(endpoint.RequestDelegate, NoOpRequestDelegate);

    private static string GetDisplayName(Endpoint endpoint)
    {
        var suffix = $"[{nameof(MetadataOnlyEndpoint)}]";
        return !string.IsNullOrEmpty(endpoint.DisplayName)
            ? endpoint.DisplayName + " " + suffix
            : suffix;
    }
}

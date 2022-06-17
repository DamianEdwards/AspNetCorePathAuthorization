using Microsoft.AspNetCore.Authorization;

namespace AspNetCore.Authorization.PathBased;

internal class PathMapPolicyDefinition
{
    public string? PolicyName { get; init; }

    public AuthorizationPolicy? Policy { get; init; }
}

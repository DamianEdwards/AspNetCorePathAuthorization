using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.Authorization.PathBased;

internal class PathMapNode
{
    public string PathSegment { get; init; } = default!;

    public Dictionary<string, PathMapNode> Children { get; } = new();

    public HashSet<AuthorizationPolicy>? DefinedPolicies { get; set; } = new();

    public AuthorizationPolicy? CombinedPolicy { get; set; }

    public bool AllowAnonymousUsers { get; set; }

    public override string ToString()
    {
        var sb = new StringBuilder();

        sb.Append($"PathSegment = {PathSegment}");
        sb.Append($", Children = {Children.Count}");

        if (AllowAnonymousUsers)
        {
            sb.Append(", AllowAnonymousUsers = true");
        }
        else if (DefinedPolicies is not null)
        {
            sb.Append($", DefinedPolicies = {DefinedPolicies.Count}");
        }
        else if (CombinedPolicy is not null)
        {
            sb.Append($", CombinedPolicy = {CombinedPolicy}");
        }

        return sb.ToString();
    }

    public (AuthorizationPolicy?, bool) GetPolicyForPath(PathString path)
    {
        if (path.Value is null) return (null, false);

        var segments = path.Value.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var currentNode = this;

        foreach (var segment in segments)
        {
            if (currentNode.Children.TryGetValue(segment, out var pathMapNode))
            {
                currentNode = pathMapNode;
            }
        }

        return (currentNode.CombinedPolicy, currentNode.AllowAnonymousUsers);
    }
}

using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.Authorization.PathBased;

internal class PathMapNode
{
    public string PathSegment { get; init; } = default!;
    public Dictionary<string, PathMapNode> Children { get; } = new();
    public AuthorizationPolicy? Policy { get; set; }
    public bool AllowAnonymous { get; set; }

    public (AuthorizationPolicy?, bool) GetAuthorizationDataForPath(PathString path)
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

        return (currentNode.Policy, currentNode.AllowAnonymous);
    }

    public override string ToString()
    {
        var sb = new StringBuilder();

        sb.Append($"PathSegment = {PathSegment}");
        sb.Append($", Children = {Children.Count}");

        if (AllowAnonymous)
        {
            sb.Append(", AllowAnonymous = true");
        }
        else if (Policy is not null)
        {
            sb.Append($", Policy = {Policy}");
        }

        return sb.ToString();
    }
}

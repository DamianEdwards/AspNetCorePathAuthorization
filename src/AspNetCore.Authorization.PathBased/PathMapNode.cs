using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.Authorization.PathBased;

internal class PathMapNode
{
    private static readonly IReadOnlyList<PathAuthorizeData> _emptyData = new List<PathAuthorizeData>();

    public Dictionary<string, PathMapNode> Children { get; } = new();

    public List<PathAuthorizeData> AuthorizeData { get; } = new();

    public AuthorizationPolicy? Policy { get; set; }

    public bool? AllowAnonymous { get; set; }

    public (IReadOnlyList<PathAuthorizeData>, AuthorizationPolicy?, bool?) GetAuthorizeDataForPath(PathString path)
    {
        if (path.Value is null) return (_emptyData, null, null);

        var segments = path.Value.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);
        var currentNode = this;

        foreach (var segment in segments)
        {
            if (currentNode.Children.TryGetValue(segment, out var pathMapNode))
            {
                currentNode = pathMapNode;
            }
        }

        return (currentNode.AuthorizeData, currentNode.Policy, currentNode.AllowAnonymous);
    }

    public override string ToString()
    {
        var sb = new StringBuilder();

        sb.Append($"Children = {Children.Count}");

        if (AllowAnonymous == true)
        {
            sb.Append(", AllowAnonymous = true");
        }
        else if (AuthorizeData.Count > 0)
        {
            sb.Append($", AuthorizeData.Count = {AuthorizeData.Count}");
        }

        return sb.ToString();
    }
}

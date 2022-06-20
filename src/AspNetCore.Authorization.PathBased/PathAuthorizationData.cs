using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.Authorization.PathBased;

internal class PathAuthorizationData
{
    public static PathAuthorizationData Empty { get; } = new();

    public PathString Path { get; init; }
    public AuthorizationPolicy? Policy { get; set; }
    public bool AllowAnonymous { get; set; }

    public override string ToString()
    {
        var sb = new StringBuilder();

        sb.Append($"Path = {Path}");

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


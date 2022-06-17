using System.Text;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.Authorization.PathBased;

internal class PathMapDefinitionEntry
{
    public PathString Path { get; init; }

    public PathMapPolicyDefinition? PolicyDefinition { get; init; } = default!;

    public bool AllowAnonymousUsers { get; init; }

    public override string ToString()
    {
        var sb = new StringBuilder();

        sb.Append($"Path = {Path}");

        if (AllowAnonymousUsers)
        {
            sb.Append(", AllowAnonymousUsers = true");
        }
        else
        {
            if (PolicyDefinition?.PolicyName is not null)
            {
                sb.Append($", PolicyName = {PolicyDefinition.PolicyName}");
            }
            else if (PolicyDefinition?.Policy is not null)
            {
                sb.Append($", Policy = {PolicyDefinition.Policy}");
            }
        }

        return sb.ToString();
    }
}

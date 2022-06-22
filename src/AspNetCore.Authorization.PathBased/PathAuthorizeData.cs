using System.Text;
using Microsoft.AspNetCore.Authorization;

namespace AspNetCore.Authorization.PathBased;

internal class PathAuthorizeData : IAuthorizeData
{
    public PathAuthorizeData()
    {

    }

    public PathAuthorizeData(IAuthorizeData source)
    {
        AuthenticationSchemes = source.AuthenticationSchemes;
        Roles = source.Roles;
        Policy = source.Policy;
    }

    public PathAuthorizeData(string policyName)
    {
        Policy = policyName;
    }

#if NET7_0_OR_GREATER
    public PathAuthorizeData(AuthorizationPolicy policy)
    {
        PolicyInstance = policy;
    }
#endif

    public string? AuthenticationSchemes { get; set; }
    
    public string? Roles { get; set; }
    
    public string? Policy { get; set; }

    public bool? AllowAnonymous { get; set; }

#if NET7_0_OR_GREATER
    public AuthorizationPolicy? PolicyInstance { get; set; }
#endif

    public override string ToString()
    {
        var sb = new StringBuilder();
        var first = true;

        if (!string.IsNullOrEmpty(AuthenticationSchemes))
        {
            if (!first) sb.Append(", ");
            sb.Append($"Schemes = {AuthenticationSchemes}");
            first = false;
        }

        if (!string.IsNullOrEmpty(Roles))
        {
            if (!first) sb.Append(", ");
            sb.Append($"Roles = {Roles}");
            first = false;
        }

        if (!string.IsNullOrEmpty(Policy))
        {
            if (!first) sb.Append(", ");
            sb.Append($"Policy = {Policy}");
            first = false;
        }

#if NET7_0_OR_GREATER
        if (PolicyInstance is not null)
        {
            if (!first) sb.Append(", ");
            sb.Append($"Policy = {PolicyInstance}");
            first = false;
        }
#endif

        if (AllowAnonymous == true)
        {
            if (!first) sb.Append(", ");
            sb.Append("AllowAnonymous = true");
            first = false;
        }

        return sb.ToString();
    }
}


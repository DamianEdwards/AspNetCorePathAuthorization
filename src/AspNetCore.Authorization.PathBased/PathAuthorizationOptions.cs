using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Razor.TagHelpers;

namespace AspNetCore.Authorization.PathBased;

/// <summary>
/// Provides programmatic configuration used by <see cref="PathAuthorizationMiddleware"/>.
/// </summary>
public class PathAuthorizationOptions
{
    private readonly Dictionary<PathString, PathAuthorizeData> _authzData = new();

    /// <summary>
    /// Require authorization for the specified path.
    /// </summary>
    /// <param name="path">The path underneath which the specificied authorization policy should apply.</param>
    public void AuthorizePath(PathString path)
    {
        _authzData[path] = new();
    }

#if NET7_0_OR_GREATER
    /// <summary>
    /// Require authorization with a specific policy for the specified path.
    /// </summary>
    /// <param name="path">The path underneath which the specificied authorization policy should apply.</param>
    /// <param name="configure">A delegate to configure the <see cref="AuthorizationPolicy"/>.</param>
    public void AuthorizePath(PathString path, Action<AuthorizationPolicyBuilder> configure)
    {
        var pb = new AuthorizationPolicyBuilder();
        configure(pb);
        var policy = pb.Build();
        _authzData[path] = new(policy);
    }

    /// <summary>
    /// Require authorization with a specific policy for the specified path.
    /// </summary>
    /// <param name="path">The path underneath which the specificied authorization policy should apply.</param>
    /// <param name="policy">The <see cref="AuthorizationPolicy"/>.</param>
    public void AuthorizePath(PathString path, AuthorizationPolicy policy)
    {
        _authzData[path] = new(policy);
    }
#endif

    /// <summary>
    /// Require authorization with a specific policy for the specified path.
    /// </summary>
    /// <param name="path">The path underneath which the specificied authorization policy should apply.</param>
    /// <param name="policy">The name of the <see cref="AuthorizationPolicy"/> to use when authorizing access to this path.</param>
    public void AuthorizePath(PathString path, string policy)
    {
        _authzData[path] = new(policy);
    }

    /// <summary>
    /// Require authorization with specific roles for the specified path.
    /// </summary>
    /// <param name="path">The path underneath which the specificied authorization policy should apply.</param>
    /// <param name="roles">A comma delimited list of roles that are allowed to access the path.</param>
    public void AuthorizePathRoles(PathString path, string roles)
    {
        _authzData[path] = new() { Roles = roles };
    }

    /// <summary>
    /// Require authorization with a specific policy for the specified path.
    /// </summary>
    /// <param name="path">The path underneath which the specificied authorization policy should apply.</param>
    /// <param name="policyName">The name of the <see cref="AuthorizationPolicy"/> that's been configured on <see cref="AuthorizationOptions"/>.</param>
    public void AuthorizePath(PathString path, IAuthorizeData data)
    {
        _authzData[path] = new(data);
    }

    /// <summary>
    /// Allow anonymous users under the specified path.
    /// </summary>
    /// <remarks>
    /// Sub-paths can still define their own policies to deny anonymous user access, e.g.
    /// <code>
    /// /           &lt;- No authorization defined
    ///   /a        &lt;- Requires authorization
    ///     /b      &lt;- Allows anonymous users
    ///       /c    &lt;- Requires authorization
    ///         /d  &lt;- Inherits authorization from c
    ///       /e    &lt;- Inherits allow anonymous users from b
    /// </code>
    /// </remarks>
    /// <param name="path">The path underneath which the anonymous users will be allowed.</param>
    public void AllowAnonymousPath(PathString path)
    {
        _authzData[path] = new() { AllowAnonymous = true };
    }

    internal PathMapNode BuildMappingTree(DefaultAuthorizationPolicyProvider? policyProvider = null)
    {
        var rootNode = new PathMapNode();

        foreach (var kvp in _authzData)
        {
            var (path, data) = kvp;

            if (data is null || path.Value is null) continue;

            var segments = path.Value.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            var currentNode = rootNode;

            // Create/walk-to node
            foreach (var segment in segments)
            {
                if (currentNode.Children.TryGetValue(segment, out var existingNode))
                {
                    currentNode = existingNode;
                }
                else
                {
                    var childNode = new PathMapNode();
                    currentNode.Children.Add(segment, childNode);
                    currentNode = childNode;
                }
            }

            // A node can have a policy but still allow anonymous users as the policy might specify an AuthN scheme
            currentNode.AuthorizeData.Add(data);
            currentNode.AllowAnonymous |= data.AllowAnonymous;
#if NET7_0_OR_GREATER
            currentNode.Policy = data.PolicyInstance;
#endif
        }

        // Walk the finished tree and gather authorization data and set on child nodes
        GatherNodeData(rootNode, null, policyProvider);
        _wrapperParentPolicyArray = null;

        return rootNode;
    }

    private static AuthorizationPolicy[]? _wrapperParentPolicyArray;

    private static void GatherNodeData(PathMapNode currentNode, PathMapNode? parentNode, DefaultAuthorizationPolicyProvider? policyProvider)
    {
        _wrapperParentPolicyArray ??= new AuthorizationPolicy[1];

#if NET7_0_OR_GREATER
        if (!currentNode.AllowAnonymous.HasValue && currentNode.AuthorizeData.Count == 0 && currentNode.Policy is null && parentNode?.AllowAnonymous.HasValue == true)
#else
        if (!currentNode.AllowAnonymous.HasValue && currentNode.AuthorizeData.Count == 0 && parentNode?.AllowAnonymous.HasValue == true)
#endif
        {
            // Inherit allow anonymous from parent
            currentNode.AllowAnonymous = true;
        }

        if (parentNode?.AuthorizeData.Count > 0)
        {
            // Copy authorize data from parent node
            currentNode.AuthorizeData.AddRange(parentNode.AuthorizeData);
        }

        if (currentNode.Policy is null && policyProvider is not null)
        {
            // The default authorization policy is synchronous and always returns the same result for the same input so we can cache the policy here
#if NET7_0_OR_GREATER
            // Setup parent policy instance
            IEnumerable<AuthorizationPolicy> parentPolicy;
            if (parentNode?.Policy is not null)
            {
                _wrapperParentPolicyArray![0] = parentNode.Policy;
                parentPolicy = _wrapperParentPolicyArray;
            }
            else
            {
                parentPolicy = Enumerable.Empty<AuthorizationPolicy>();
            }

            currentNode.Policy = AuthorizationPolicy.CombineAsync(policyProvider, currentNode.AuthorizeData, parentPolicy).GetAwaiter().GetResult();

            // Policy is combined now so we can clear out the data, children will combine with the policy instance
            currentNode.AuthorizeData.Clear();
#else
            currentNode.Policy = AuthorizationPolicy.CombineAsync(policyProvider, currentNode.AuthorizeData).GetAwaiter().GetResult();
#endif
        }

        // Visit children
        foreach (var kvp in currentNode.Children)
        {
            var (_, childNode) = kvp;
            GatherNodeData(childNode, currentNode, policyProvider);
        }
    }
}

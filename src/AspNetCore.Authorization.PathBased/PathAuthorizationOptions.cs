using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.Authorization.PathBased;

/// <summary>
/// Provides programmatic configuration used by <see cref="PathAuthorizationMiddleware"/>.
/// </summary>
public class PathAuthorizationOptions
{
    private Dictionary<PathString, PathAuthorizationData> PathMapDefinitions { get; } = new();

    /// <summary>
    /// Add an authorization policy for the specified path.
    /// </summary>
    /// <param name="path">The path underneath which the specificied authorization policy should apply.</param>
    /// <param name="configure">A delegate to configure the <see cref="AuthorizationPolicy"/>.</param>
    public void AuthorizePath(PathString path)
    {
        PathMapDefinitions[path] = new() { Path = path };
    }

    /// <summary>
    /// Add an authorization policy for the specified path.
    /// </summary>
    /// <param name="path">The path underneath which the specificied authorization policy should apply.</param>
    /// <param name="configure">A delegate to configure the <see cref="AuthorizationPolicy"/>.</param>
    public void AuthorizePath(PathString path, Action<AuthorizationPolicyBuilder> configure)
    {
        var pb = new AuthorizationPolicyBuilder();
        configure(pb);
        AuthorizePath(path, pb.Build());
    }

    /// <summary>
    /// Add an authorization policy for the specified path.
    /// </summary>
    /// <param name="path">The path underneath which the specificied authorization policy should apply.</param>
    /// <param name="policy">The <see cref="AuthorizationPolicy"/>.</param>
    public void AuthorizePath(PathString path, AuthorizationPolicy policy)
    {
        PathMapDefinitions[path] = new() { Path = path, Policy = policy };
    }

    /// <summary>
    /// Add an authorization policy for the specified path.
    /// </summary>
    /// <param name="path">The path underneath which the specificied authorization policy should apply.</param>
    /// <param name="policyName">The name of the <see cref="AuthorizationPolicy"/> that's been configured on <see cref="AuthorizationOptions"/>.</param>
    public void AuthorizePath(PathString path, string policyName)
    {
        PathMapDefinitions[path] = new() { Path = path, Policy = new NamedPolicyPlaceholder(policyName) };
    }

    /// <summary>
    /// Add a path to allow anonymous users under.
    /// </summary>
    /// <remarks>
    /// Sub-paths can still define their own policies to deny anonymous user access, e.g.
    /// <code>
    /// /           &lt;- No authorization policies defined
    ///   /a        &lt;- Requires authorization
    ///     /b      &lt;- Allows anonymous users
    ///       /c    &lt;- Requires authorization
    ///         /d  &lt;- Inherits authorization policies from c
    ///       /e    &lt;- Inherits allow anonymous users from b
    /// </code>
    /// </remarks>
    /// <param name="path">The path underneath which the anonymous users will be allowed.</param>
    public void AllowAnonymousPath(PathString path)
    {
        PathMapDefinitions[path] = new() { Path = path, AllowAnonymous = true };
    }

    internal PathMapNode BuildMappingTree(AuthorizationOptions authzOptions)
    {
        var rootNode = new PathMapNode { PathSegment = "/" };

        foreach (var kvp in PathMapDefinitions)
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
                    var childNode = new PathMapNode { PathSegment = segment };
                    currentNode.Children.Add(segment, childNode);
                    currentNode = childNode;
                }
            }

            // A node can have a policy but still allow anonymous users as the policy might specify an AuthN scheme
            currentNode.AllowAnonymous = data.AllowAnonymous;
            currentNode.Policy = data.Policy switch
            {
                NamedPolicyPlaceholder namedPolicy => authzOptions.GetPolicy(namedPolicy.PolicyName)
                    ?? throw new InvalidOperationException($"An authorization policy with name '{namedPolicy.PolicyName}' was not found."),
                { } policy => policy,
                // TODO: Not sure of the impact of using DefaultPolicy here vs. letting AuthorizationPolicy.CombineAsync do it per-request
                _ => authzOptions.DefaultPolicy
            };
        }

        // Walk the finished tree and gather authorization data and set on child nodes
        GatherNodeData(rootNode, null);

        return rootNode;
    }

    private static void GatherNodeData(PathMapNode currentNode, PathMapNode? parentNode)
    {
        if (currentNode.Policy is null)
        {
            // Copy authorize data from parent node
            currentNode.Policy = parentNode?.Policy;
            currentNode.AllowAnonymous = parentNode?.AllowAnonymous ?? false;
        }
        else if (currentNode.Policy is not null && parentNode?.Policy is not null)
        {
            // Combine with parent policy
            // TODO: Not sure about the impact of combining here vs. doing it per-request with CombineAsync
            currentNode.Policy = AuthorizationPolicy.Combine(parentNode.Policy, currentNode.Policy);
        }

        // Visit children
        foreach (var kvp in currentNode.Children)
        {
            var (_, childNode) = kvp;
            GatherNodeData(childNode, currentNode);
        }
    }

    private class NamedPolicyPlaceholder : AuthorizationPolicy
    {
        private static readonly PlaceholderRequirement[] _requirements = new[] { new PlaceholderRequirement() };

        public NamedPolicyPlaceholder(string policyName)
            : base(_requirements, Enumerable.Empty<string>())
        {
            PolicyName = policyName;
        }

        public string PolicyName { get; }

        public override string ToString() => $"NamedPolicyPlaceholder.PolicyName = {PolicyName}";
    }

    private class PlaceholderRequirement : IAuthorizationRequirement
    {
        
    }
}

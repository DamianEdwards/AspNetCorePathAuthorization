using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;

namespace AspNetCore.Authorization.PathBased;

/// <summary>
/// Provides programmatic configuration used by <see cref="PathAuthorizationMiddleware"/>.
/// </summary>
public class PathAuthorizationOptions
{
    private Dictionary<PathString, PathMapDefinitionEntry> PathMapDefinitions { get; } = new();

    /// <summary>
    /// Add an authorization policy for the specified path.
    /// </summary>
    /// <param name="path">The path underneath which the specificied authorization policy should apply.</param>
    /// <param name="configure">A delegate to configure the <see cref="AuthorizationPolicy"/>.</param>
    public void AddPathPolicy(PathString path, Action<AuthorizationPolicyBuilder> configure)
    {
        var pb = new AuthorizationPolicyBuilder();
        configure(pb);
        AddPathPolicy(path, pb.Build());
    }

    /// <summary>
    /// Add an authorization policy for the specified path.
    /// </summary>
    /// <param name="path">The path underneath which the specificied authorization policy should apply.</param>
    /// <param name="policy">The <see cref="AuthorizationPolicy"/>.</param>
    public void AddPathPolicy(PathString path, AuthorizationPolicy policy)
    {
        PathMapDefinitions[path] = new() { Path = path, PolicyDefinition = new() { Policy = policy } };
    }

    /// <summary>
    /// Add an authorization policy for the specified path.
    /// </summary>
    /// <param name="path">The path underneath which the specificied authorization policy should apply.</param>
    /// <param name="policyName">The name of the <see cref="AuthorizationPolicy"/> that's been configured on <see cref="AuthorizationOptions"/>.</param>
    public void AddPathPolicy(PathString path, string policyName)
    {
        PathMapDefinitions[path] = new() { Path = path, PolicyDefinition = new() { PolicyName = policyName } };
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
    public void AddAllowAnonymousPath(PathString path)
    {
        PathMapDefinitions[path] = new() { Path = path, AllowAnonymousUsers = true };
    }

    internal PathMapNode BuildMappingTree(AuthorizationOptions authzOptions)
    {
        var rootNode = new PathMapNode { PathSegment = "/" };

        foreach (var kvp in PathMapDefinitions)
        {
            var (path, entry) = kvp;

            if (entry is null || path.Value is null) continue;

            var segments = path.Value.Split('/', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries);

            var currentNode = rootNode;

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

            if (!entry.AllowAnonymousUsers)
            {
                // Apply policies
                var resolvedPolicy = entry.PolicyDefinition?.Policy
                    ?? authzOptions.GetPolicy(entry.PolicyDefinition?.PolicyName!)
                    ?? throw new InvalidOperationException($"An authorization policy with name '{entry.PolicyDefinition?.PolicyName}' was not found.");

                if (currentNode.DefinedPolicies is null)
                {
                    throw new InvalidOperationException("Invalid node state detected while building tree.");
                }

                currentNode.DefinedPolicies.Add(resolvedPolicy);
            }
            else
            {
                currentNode.AllowAnonymousUsers = true;
            }
        }

        // Walk the finished tree and gather policies to add to leaf nodes
        var policies = new HashSet<AuthorizationPolicy>();
        var allowAnonymous = rootNode.AllowAnonymousUsers;
        GatherLeafNodePolicies(rootNode, policies, ref allowAnonymous);

        return rootNode;
    }

    private static void GatherLeafNodePolicies(PathMapNode currentNode, HashSet<AuthorizationPolicy> policies, ref bool allowAnonymous)
    {
        if (!allowAnonymous && currentNode.DefinedPolicies is { } currentNodePolicies)
        {
            // Add current node policies to gathered policies
            foreach (var policy in currentNodePolicies)
            {
                policies.Add(policy);
            }
        }
        else
        {
            // Anonymous users allowed, clear gathered policies
            policies.Clear();
        }

        // Collapse current node's policies
        if (policies.Count > 0)
        {
            currentNode.CombinedPolicy = AuthorizationPolicy.Combine(policies);
            currentNode.DefinedPolicies?.Clear();
            currentNode.DefinedPolicies = null;
        }

        // Visit children
        foreach (var kvp in currentNode.Children)
        {
            var (_, node) = kvp;
            GatherLeafNodePolicies(node, policies, ref allowAnonymous);
        }

        policies.Clear();
        allowAnonymous = false;
    }
}

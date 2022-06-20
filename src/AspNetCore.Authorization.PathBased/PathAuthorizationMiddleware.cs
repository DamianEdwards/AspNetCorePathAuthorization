using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Policy;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace AspNetCore.Authorization.PathBased;

/// <summary>
/// A middleware that performs authorization based on the current request path.
/// </summary>
public class PathAuthorizationMiddleware
{
    // AppContext switch used to control whether HttpContext or endpoint is passed as a resource to AuthZ
    private const string SuppressUseHttpContextAsAuthorizationResource = "Microsoft.AspNetCore.Authorization.SuppressUseHttpContextAsAuthorizationResource";

    private readonly RequestDelegate _next;
    private readonly IAuthorizationService _authorizationService;
    private readonly IAuthorizationPolicyProvider _authorizationPolicyProvider;
    private readonly PathAuthorizationOptions? _pathAuthorizationOptions;
    private readonly AuthorizationOptions? _authorizationOptions;
    private readonly PathMapNode _pathMapTree;

    /// <summary>
    /// Creates a new instance of <see cref="PathAuthorizationMiddleware"/>.
    /// </summary>
    /// <param name="next">The next <see cref="RequestDelegate"/> in the pipeline.</param>
    /// <param name="authorizationService">The <see cref="IAuthorizationService"/>.</param>
    /// <param name="authorizationOptions">The <see cref="IOptions{AuthorizationOptions}"/>.</param>
    /// <param name="pathAuthorizationOptions">The <see cref="IOptions{PathAuthorizationOptions}"/>.</param>
    public PathAuthorizationMiddleware(RequestDelegate next,
        IAuthorizationService authorizationService,
        IAuthorizationPolicyProvider authorizationPolicyProvider,
        IOptions<AuthorizationOptions> authorizationOptions,
        IOptions<PathAuthorizationOptions> pathAuthorizationOptions)
    {
        _next = next;
        _authorizationService = authorizationService;
        _authorizationPolicyProvider = authorizationPolicyProvider;
        _authorizationOptions = authorizationOptions.Value;
        _pathAuthorizationOptions = pathAuthorizationOptions.Value;
        _pathMapTree = _pathAuthorizationOptions.BuildMappingTree(_authorizationOptions);
    }

    /// <summary>
    /// Runs the middleware.
    /// </summary>
    /// <param name="context">The <see cref="HttpContext"/> for the current request.</param>
    /// <returns>A <see cref="Task"/> representing the execution.</returns>
    /// <exception cref="InvalidOperationException"></exception>
    public async Task InvokeAsync(HttpContext context)
    {
        var endpoint = context.GetEndpoint();

        var (policy, allowAnonymous) = _pathMapTree.GetAuthorizationDataForPath(context.Request.Path);

        if (policy is null)
        {
            // No authorization to apply
            await _next(context);
            return;
        }

        // Policy evaluator has transient lifetime so it's fetched from request services instead of injecting in constructor
        var policyEvaluator = context.RequestServices.GetRequiredService<IPolicyEvaluator>();

        // Authenticate using the policy schemes
        var authenticateResult = await policyEvaluator.AuthenticateAsync(policy, context);

        if (authenticateResult.Succeeded)
        {
            if (context.Features.Get<IAuthenticateResultFeature>() is IAuthenticateResultFeature authenticateResultFeature)
            {
                authenticateResultFeature.AuthenticateResult = authenticateResult;
            }
            else
            {
                var authFeatures = new AuthenticationFeatures(authenticateResult);
                context.Features.Set<IHttpAuthenticationFeature>(authFeatures);
                context.Features.Set<IAuthenticateResultFeature>(authFeatures);
            }
        }

        // Allow Anonymous still wants to run authorization to populate the User but skips any failure/challenge handling
        if (allowAnonymous || endpoint?.Metadata.GetMetadata<IAllowAnonymous>() != null)
        {
            await _next(context);
            return;
        }

        object? resource;
        if (AppContext.TryGetSwitch(SuppressUseHttpContextAsAuthorizationResource, out var useEndpointAsResource) && useEndpointAsResource)
        {
            resource = endpoint;
        }
        else
        {
            resource = context;
        }

        var authorizeResult = await policyEvaluator.AuthorizeAsync(policy, authenticateResult, context, resource);
        var authorizationMiddlewareResultHandler = context.RequestServices.GetRequiredService<IAuthorizationMiddlewareResultHandler>();
        await authorizationMiddlewareResultHandler.HandleAsync(_next, context, policy, authorizeResult);
    }
}

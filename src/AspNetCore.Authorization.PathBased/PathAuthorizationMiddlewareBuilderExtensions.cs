using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.Http;
using AspNetCore.Authorization.PathBased;

namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Extension methods for adding <see cref="PathAuthorizationMiddleware"/> via <see cref="IApplicationBuilder"/>.
/// </summary>
public static class PathAuthorizationMiddlewareBuilderExtensions
{
    /// <summary>
    /// Adds middleware that performs authorization based on the current request path.
    /// </summary>
    /// <param name="builder">The <see cref="IApplicationBuilder"/>.</param>
    /// <param name="configure">A delegate to configure the <see cref="PathAuthorizationOptions"/> that defines the path-based authorization rules.</param>
    /// <returns>The <see cref="IApplicationBuilder"/>.</returns>
    public static IApplicationBuilder UsePathAuthorization(this IApplicationBuilder builder, Action<PathAuthorizationOptions> configure)
    {
        var options = new PathAuthorizationOptions();
        configure(options);
        return UsePathAuthorization(builder, options);
    }

    /// <summary>
    /// Adds middleware that performs authorization based on the current request path.
    /// </summary>
    /// <param name="builder">The <see cref="IApplicationBuilder"/>.</param>
    /// <param name="options">The <see cref="PathAuthorizationOptions"/> that defines the path-based authorization rules.</param>
    /// <returns>The <see cref="IApplicationBuilder"/>.</returns>
    public static IApplicationBuilder UsePathAuthorization(this IApplicationBuilder builder, PathAuthorizationOptions options)
    {
        builder.UseMiddleware<PathAuthorizationMiddleware>(Options.Create(options));
        return builder;
    }

    /// <summary>
    /// Adds middleware that performs authorization based on the current request path.
    /// </summary>
    /// <param name="builder">The <see cref="IApplicationBuilder"/>.</param>
    /// <returns>The <see cref="IApplicationBuilder"/>.</returns>
    public static IApplicationBuilder UsePathAuthorization(this IApplicationBuilder builder)
    {
        builder.UseMiddleware<PathAuthorizationMiddleware>();
        return builder;
    }

    /// <summary>
    /// Require authorization for the specified path using the default policy.
    /// </summary>
    /// <typeparam name="T">The specific <see cref="IEndpointRouteBuilder"/> type.</typeparam>
    /// <param name="builder">The <typeparamref name="T"/> builder.</param>
    /// <param name="path">The path underneath which authorization should apply.</param>
    /// <returns>An <see cref="IEndpointConventionBuilder"/> that can be used to further customize the endpoint.</returns>
    public static IEndpointConventionBuilder RequireAuthorization<T>(this T builder, PathString path)
        where T : IEndpointRouteBuilder
    {
        var pattern = path + new PathString("/{**subpath}");
        return builder.MapMetadata(pattern.Value!).RequireAuthorization();
    }

    /// <summary>
    /// Require authorization for the specified path using the supplied role names.
    /// </summary>
    /// <typeparam name="T">The specific <see cref="IEndpointRouteBuilder"/> type.</typeparam>
    /// <param name="builder">The <typeparamref name="T"/> builder.</param>
    /// <param name="path">The path underneath which authorization should apply.</param>
    /// <param name="roleNames">A comma delimited list of roles that are allowed to access the resource.</param>
    /// <returns>An <see cref="IEndpointConventionBuilder"/> that can be used to further customize the endpoint.</returns>
    public static IEndpointConventionBuilder RequireAuthorizationWithRoles<T>(this T builder, PathString path, string roleNames)
        where T : IEndpointRouteBuilder
    {
        var pattern = path + new PathString("/{**subpath}");
        return builder.MapMetadata(pattern.Value!).RequireAuthorization(new AuthorizeAttribute { Roles = roleNames });
    }

    /// <summary>
    /// Require authorization for the specified path using the specified policies.
    /// </summary>
    /// <typeparam name="T">The specific <see cref="IEndpointRouteBuilder"/> type.</typeparam>
    /// <param name="builder">The <typeparamref name="T"/> builder.</param>
    /// <param name="path">The path underneath which authorization should apply.</param>
    /// <param name="policy">The name of the <see cref="AuthorizationPolicy"/> to use when authorizing access to this path.</param>
    /// <returns>An <see cref="IEndpointConventionBuilder"/> that can be used to further customize the endpoint.</returns>
    public static IEndpointConventionBuilder RequireAuthorization<T>(this T builder, PathString path, params string[] policyNames)
        where T : IEndpointRouteBuilder
    {
        var pattern = path + new PathString("/{**subpath}");
        return builder.MapMetadata(pattern.Value!).RequireAuthorization(policyNames);
    }

    /// <summary>
    /// Require authorization for the specified path using the specified <see cref="IAuthorizeData"/>.
    /// </summary>
    /// <typeparam name="T">The specific <see cref="IEndpointRouteBuilder"/> type.</typeparam>
    /// <param name="builder">The <typeparamref name="T"/> builder.</param>
    /// <param name="path">The path underneath which authorization should apply.</param>
    /// <param name="authorizeData">The collection of <see cref="IAuthorizeData"/>. If empty, the default authorization policy will be used.</param>
    /// <returns>An <see cref="IEndpointConventionBuilder"/> that can be used to further customize the endpoint.</returns>
    public static IEndpointConventionBuilder RequireAuthorization<T>(this T builder, PathString path, params IAuthorizeData[] authorizeData)
        where T : IEndpointRouteBuilder
    {
        var pattern = path + new PathString("/{**subpath}");
        return builder.MapMetadata(pattern.Value!).RequireAuthorization(authorizeData);
    }

#if NET7_0_OR_GREATER
    /// <summary>
    /// Require authorization for the specified path using a policy configured by a callback.
    /// </summary>
    /// <typeparam name="T">The specific <see cref="IEndpointRouteBuilder"/> type.</typeparam>
    /// <param name="builder">The <typeparamref name="T"/> builder.</param>
    /// <param name="path">The path underneath which authorization should apply.</param>
    /// <param name="configurePolicy">The callback used to configure the policy</param>
    /// <returns>An <see cref="IEndpointConventionBuilder"/> that can be used to further customize the endpoint.</returns>
    public static IEndpointConventionBuilder RequireAuthorization<T>(this T builder, PathString path, Action<AuthorizationPolicyBuilder> configurePolicy)
        where T : IEndpointRouteBuilder
    {
        var pattern = path + new PathString("/{**subpath}");
        return builder.MapMetadata(pattern).RequireAuthorization(configurePolicy);
    }
#endif

    /// <summary>
    /// Allows anonymous access to the specified path by adding an <see cref="AllowAnonymousAttribute" /> to the metadata. This will bypass
    /// all authorization checks under this path including the default authorization policy and fallback authorization policy.
    /// </summary>
    /// <typeparam name="T"></typeparam>
    /// <param name="builder"></param>
    /// <param name="path"></param>
    /// <returns></returns>
    public static IEndpointConventionBuilder AllowAnonymous<T>(this T builder, PathString path)
        where T : IEndpointRouteBuilder
    {
        var pattern = path + new PathString("/{**subpath}");
        return builder.MapMetadata(pattern.Value!).AllowAnonymous();
    }
}

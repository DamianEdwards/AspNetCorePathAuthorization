using Microsoft.Extensions.Options;
using AspNetCore.Authorization.PathBased;

namespace Microsoft.AspNetCore.Builder;

/// <summary>
/// Extension methods for adding <see cref="PathAuthorizationMiddleware"/> via <see cref="IApplicationBuilder"/>.
/// </summary>
public static class PathAuthorizationMiddlewareApplicationBuilderExtensions
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
}

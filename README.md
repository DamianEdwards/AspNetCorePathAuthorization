# AspNetCore.Authorization.PathBased

Demonstrates how one might do path-based authorization in an ASP.NET Core application.

ASP.NET Core's authorization system is based on metadata associated with routing endpoints. But what if you want to add authorization based on the path of the current request instead (like you could in System.Web using the `<location>` element in the *web.config* file)? For example, you'd like to protect anything accessed at or under the `/admin` path with a policy that only allows users with a specific claim, or in a specific role. This repo demonstrates how you can do that using two different approaches:

- A custom authorization middleware
- Endpoint metadata decoration (whether there's an endpoint registered on that path or not)

## Using the middleware

Example usage:

```csharp
app.UseAuthentication();
app.UseAuthorization();
app.UsePathAuthorization(options =>
{
    // Authorize using default policy
    options.AuthorizePath("/users");
    // Authorize using inline-defined policy (net7.0 only)
    options.AuthorizePath("/management", policy =>
        policy.RequireAuthenticatedUser()
              .RequireRole("Managers"));
    // Authorize using role names
    options.AuthorizePathRoles("/management", "Managers");
    // Allow anonymous users under a sub-path of an authorized path
    options.AllowAnonymousPath("/management/feedback");
    // Authorize using named policy
    options.AuthorizePath("/admin", "AdminsOnly");
});
```

### Middleware implementation points

- Sub-paths of protected paths can allow anonymous users, e.g. `/management/feedback` in the example above
- Endpoints that exist under protected paths can opt-in to allow anonymous users in the normal way and that will be honored
- The middleware only evaluates path-based authorization rules and thus should be used in conjunction with ASP.NET Core's included authorization middleware (i.e. you should still call `app.UseAuthorization()`)
- The path protection mappings are stored in a prefix trie that's computed from the configured options at app startup to improve performance (see the second approach below for an example of how to avoid this step altogether)

## Using the endpoint metadata decorator

Example usage:

```csharp
app.UseAuthentication();
app.UseAuthorization();

app.RequireAuthorization("/test");
app.MapGet("/test/sub", () => "This endpoint requires authorization");

app.MapGet("/", () => "Hello World!");

app.RequireAuthorization("/users");
app.MapGet("/users", (HttpContext context) => $"Hello {context.User.Identity?.Name ?? "[unknown]"}!");

app.RequireAuthorizationWithRoles("/management", "Managers");
app.AllowAnonymous("/management/feedback");
app.MapGet("/management", () => $"Management portal");
app.MapGet("/management/{job}", (string job) => $"Management is busy doing the following job: {job}");
app.MapGet("/management/feedback", (HttpContext context) => $"Thanks for your feedback {context.User.Identity?.Name}");

app.RequireAuthorization("/admin", "AdminsOnly");
app.MapGet("/admin", () => $"Admin portal");
app.MapGet("/admin/{action}", (string action) => $"Only admins can {action} and you're an admin so you can {action}.");
```

### Endpoint metadata decorators implementation points

- This adds metadata to existing endpoints in the application's route tree so path matching is performed as part of normal routing meaning no extra perf hit per request!
- The authorization is performed by the usual authorization middleware, there's no custom middleware involved, so the normal rules with regards to authorization policy combination, authentication scheme selection, controlling the authorization result behavior, etc. apply
- The underlying mechanism to decorate endpoints with extra metadata is completely reusable and could enable other endpoint-aware middleware (e.g. output caching) to work with non-endpoint aware middleware (e.g. static files).
- See [this announcement on the ASP.NET Core repo](https://github.com/aspnet/Announcements/issues/488) for more details about a change in .NET 7 that will enable this approach to work well with the existing file-serving middleware in ASP.NET Core.

## Sample app & authentication

See the [samples/SampleSite](samples/SampleSite) project for an example of how to add and configure it. The sample site uses a simple query string based authentication handler so you can send requests like the following to easily simulate different users:

- `/users?name=WorkerPerson`
- `/users/ForUsersOnly.html?name=WorkerPerson`
- `/management?name=MsManager&role=Managers`
- `/management/feedback`
- `/management/feedback?name=WorkerPerson`
- `/admin?name=admin`
- `/admin?name=MsManager`

## Misc

- **This hasn't been security reviewed, or even code reviewed, so use at your own risk!**
- Feel free to log issues or send pull requests and I'll do my best to look at them.
- Reach out to me at [twitter.com/damianedwards](https://twitter.com/damianedwards) if you have any questions

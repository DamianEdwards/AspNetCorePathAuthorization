# AspNetCore.Authorization.PathBased

A middleware to enable path-based authorization in an ASP.NET Core application.

ASP.NET Core's authorization system is based on metadata associated with routing endpoints. But what if you want to add authorization based on the path of the current request instead (like you could in System.Web using the `<location>` element in the *web.config* file)? For example, you'd like to protect anything accessed at or under the `/admin` path with a policy that only allows users with a specific claim, or in a specific role. This middleware allows you to do that.

Example usage:

```csharp
app.UseAuthentication();
app.UseAuthorization();
app.UsePathAuthorization(options =>
{
    // Authorize using default policy
    options.AuthorizePath("/users");
    // Authorize using inline-defined policy
    options.AuthorizePath("/management", policy =>
        policy.RequireAuthenticatedUser()
              .RequireRole("Managers"));
    // Allow anonymous users under a sub-path of an authorized path
    options.AllowAnonymousPath("/management/feedback");
    // Authorize using named policy
    options.AuthorizePath("/admin", "AdminsOnly");
});
```

See the [samples/SampleSite](samples/SampleSite) project for an example of how to add and configure it. The sample site uses a simple query string based authentication handler so you can send requests like the following to easily simulate different users:

- `/users?name=WorkerPerson`
- `/users/ForUsersOnly.html?name=WorkerPerson`
- `/management?name=MsManager&role=Managers`
- `/management/feedback`
- `/management/feedback?name=WorkerPerson`
- `/admin?name=admin`
- `/admin?name=MsManager`

## Implementation points

- Sub-paths of protected paths can allow anonymous users, e.g. `/management/feedback` in the example above
- Endpoints that exist under protected paths can opt-in to allow anonymous users in the normal way and that will be honored
- This middleware only evaluates path-based authorization rules and thus should be used in conjunction with ASP.NET Core's included authorization middleware (i.e. you should still call `app.UseAuthorization()`)
- The path protection mappings are stored in a prefix trie that's computed from the configured options at app startup to improve performance but ideally ASP.NET Core's routing system would include support for adding routes for purposes like this too to avoid the need to have multiple stages in each request walking the path segments
- **This hasn't been security reviewed, or even code reviewed, so use at your own risk!**
- Feel free to log issues or send pull requests and I'll do my best to look at them.

[twitter.com/damianedwards](https://twitter.com/damianedwards)
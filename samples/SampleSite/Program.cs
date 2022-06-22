using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("QueryAuth")
    .AddScheme<AuthenticationSchemeOptions, QueryAuthScheme>("QueryAuth", options => { });
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminsOnly", policy =>
        policy.RequireAuthenticatedUser()
              .RequireUserName("admin"));
});

var app = builder.Build();

app.UseStatusCodePages();

app.UseAuthentication();
app.UseAuthorization();
app.UsePathAuthorization(options =>
{
    // Authorize using default policy
    options.AuthorizePath("/users");
#if NET7_0_OR_GREATER
    // Authorize using inline-defined policy
    options.AuthorizePath("/management", policy =>
        policy.RequireAuthenticatedUser()
              .RequireRole("Managers"));
#else
    // Authorize using role names
    options.AuthorizePathRoles("/management", "Managers");
#endif
    // Allow anonymous users under a sub-path of an authorized path
    options.AllowAnonymousPath("/management/feedback");
    // Authorize using named policy
    options.AuthorizePath("/admin", "AdminsOnly");
});

app.UseStaticFiles();

app.MapGet("/", () => "Hello World!");
app.MapGet("/users", (HttpContext context) => $"Hello {context.User.Identity?.Name ?? "[unknown]"}!");
app.MapGet("/management", () => $"Management portal");
app.MapGet("/management/{job}", (string job) => $"Management is busy doing the following job: {job}");
app.MapGet("/management/feedback", (HttpContext context) => $"Thanks for your feedback {context.User.Identity?.Name}");
app.MapGet("/admin", () => $"Admin portal");
app.MapGet("/admin/{action}", (string action) => $"Only admins can {action} and you're an admin so you can {action}.");

app.Run();

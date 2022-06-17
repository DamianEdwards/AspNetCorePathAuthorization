using Microsoft.AspNetCore.Authentication;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("QueryAuth")
    .AddScheme<AuthenticationSchemeOptions, QueryAuthScheme>("QueryAuth", options => { });
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AuthenticatedUsers", policy =>
        policy.RequireAuthenticatedUser());

    options.AddPolicy("Managers", policy =>
        policy.RequireAuthenticatedUser()
            .RequireRole("Managers"));

    options.AddPolicy("AdminsOnly", policy =>
        policy.RequireAuthenticatedUser()
            .RequireClaim("IsAdmin"));
});

var app = builder.Build();

app.UseStatusCodePages();

app.UseAuthentication();
app.UseAuthorization();
app.UsePathAuthorization(options =>
{
    options.AddPathPolicy("/users", "AuthenticatedUsers");
    options.AddPathPolicy("/management", "Managers");
    options.AddAllowAnonymousPath("/management/feedback");
    options.AddPathPolicy("/admin", "AdminsOnly");
});

app.UseStaticFiles();

app.MapGet("/", () => "Hello World!");
app.MapGet("/users", (HttpContext context) => $"Hello {context.User.Identity?.Name ?? "[unknown]"}!");
app.MapGet("/management", () => $"Management portal");
app.MapGet("/management/{job}", (string job) => $"Management is busy doing the following job: {job}");
app.MapGet("/management/feedback", () => $"Thanks for your feedback");
app.MapGet("/admin", () => $"Admin portal");
app.MapGet("/admin/{action}", (string action) => $"Only admins can {action} and you're an admin so you can {action}.");

app.Run();

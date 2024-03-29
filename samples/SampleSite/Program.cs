﻿using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddAuthentication("QueryAuth")
    .AddScheme<AuthenticationSchemeOptions, QueryAuthScheme>("QueryAuth", options => { });
builder.Services.AddAuthorization(options =>
{
    options.AddPolicy("AdminsOnly", policy =>
        policy.RequireAuthenticatedUser()
              .RequireUserName("admin"));
});

builder.Services.AddEndpointMetadataDecorators();

var app = builder.Build();

app.UseStatusCodePages();

app.UseAuthentication();
app.UseAuthorization();

// The following block demonstrates how to use the middleware approach
//app.UsePathAuthorization(options =>
//{
//    // Authorize using default policy
//    options.AuthorizePath("/users");
//#if NET7_0_OR_GREATER
//    // Authorize using inline-defined policy
//    options.AuthorizePath("/management", policy =>
//        policy.RequireAuthenticatedUser()
//              .RequireRole("Managers"));
//#else
//    // Authorize using role names
//    options.AuthorizePathRoles("/management", "Managers");
//#endif
//    // Allow anonymous users under a sub-path of an authorized path
//    options.AllowAnonymousPath("/management/feedback");
//    // Authorize using named policy
//    options.AuthorizePath("/admin", "AdminsOnly");
//});

app.UseStaticFiles(ConfigureStaticFiles());

app.MapMetadata("/{**subpath}").WithMetadata(new { Whatever = "This is on every endpoint now!" });

app.MapGet("/printmetadata", (HttpContext context) => context.GetEndpoint()?.Metadata
    .Select(m => new { TypeName = m.GetType().FullName, Value = m.ToString() }))
    .WithMetadata(new { Value = "This is only on this single endpoint" });

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

app.Run();

StaticFileOptions ConfigureStaticFiles() => new ()
    {
        OnPrepareResponse = ctx =>
        {
            var endpoint = ctx.Context.GetEndpoint();
            // Ensure response isn't cached if endpoint requires authorization
            if (endpoint?.Metadata.GetMetadata<IAuthorizeData>() is { }
                && endpoint?.Metadata.GetMetadata<IAllowAnonymous>() is null)
            {
                ctx.Context.Response.Headers.CacheControl = "must-revalidate";
            }
        }
    };

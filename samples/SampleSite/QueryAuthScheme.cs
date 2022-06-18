using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Options;
using System.Security.Claims;
using System.Text.Encodings.Web;

namespace Microsoft.AspNetCore.Authentication;

/// <summary>
/// This is NOT a real authentication scheme. Don't ever use it on a real site. It's just
/// intended to make exploring the *authorization* setup of this sample site easy by allowing
/// you to specify user details for the request via the query string.
/// </summary>
public class QueryAuthScheme : AuthenticationHandler<AuthenticationSchemeOptions>
{
    public QueryAuthScheme(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder urlEncoder, ISystemClock clock)
        : base(options, logger, urlEncoder, clock)
    {

    }

    protected override Task<AuthenticateResult> HandleAuthenticateAsync()
    {
        var nameQuery = Context.Request.Query["name"];
        if (nameQuery.Count == 0)
        {
            return Task.FromResult(AuthenticateResult.Fail("No user name provided in querystring (?name=)"));
        }

        var identity = new ClaimsIdentity("QueryAuth");
        identity.AddClaim(new Claim(ClaimTypes.Name, nameQuery));

        if (nameQuery == "admin")
        {
            identity.AddClaim(new Claim("IsAdmin", "true"));
        }

        var roleQuery = Context.Request.Query["role"];
        foreach (var role in roleQuery)
        {
            identity.AddClaim(new Claim(identity.RoleClaimType, role));
        }

        var user = new ClaimsPrincipal(identity);
        return Task.FromResult(AuthenticateResult.Success(new AuthenticationTicket(user, nameof(QueryAuthScheme))));
    }
}

using Duende.IdentityServer.Events;
using Duende.IdentityServer;
using Duende.IdentityServer.Services;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.VisualBasic;
using System.Security.Claims;

namespace identity.server.bff.v3;

public static class ExternalAuthEndpointGroup
{
    public static RouteGroupBuilder ExternalAuthGroup(this RouteGroupBuilder group)
    {
        group.MapGet("/google", (string returnUrl, HttpContext httpContext) => {
            //string provider, string returnUrl, 
            //if (returnUrl.IsLocalUrl(httpContext.Request))
            //    return Results.BadRequest("Invalid return URL");

            var props = new AuthenticationProperties()
            {
                RedirectUri = $"/auth/external-callback",
                Items =
                {
                    { "uru", returnUrl },
                    { "scheme", "Google" }
                }
            };

            var authSchemes = new List<string>()
            {
                "Google"
            };

            //var properties = signInManager.ConfigureExternalAuthenticationProperties(provider, redurectUrl);

            return Results.Challenge(props, authSchemes);
        });

        group.MapGet("/external-callback", async (HttpContext httpContext, IIdentityServerInteractionService interaction, IEventService events) =>
        {
            var result = await httpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
            if (result.Succeeded != true)
            {
                throw new InvalidOperationException($"External authentication error: {result.Failure}");
            }

            var externalUser = result.Principal ??
                throw new InvalidOperationException("External authentication produced a null Principal");
          

            // lookup our user and external provider info
            // try to determine the unique id of the external user (issued by the provider)
            // the most common claim type for that are the sub claim and the NameIdentifier
            // depending on the external provider, some other claim type might be used
            var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                              externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
                              throw new InvalidOperationException("Unknown userid");

            var provider = result.Properties.Items["scheme"] ?? throw new InvalidOperationException("Null scheme in authentiation properties");
            var providerUserId = userIdClaim.Value;

            var subjId = externalUser.FindFirst(ClaimTypes.NameIdentifier)?.Value;

            // this allows us to collect any additional claims or properties
            // for the specific protocols used and store them in the local auth cookie.
            // this is typically used to store data needed for signout from those protocols.
            var additionalLocalClaims = new List<Claim>();
            var localSignInProps = new AuthenticationProperties();
            CaptureExternalLoginContext(result, additionalLocalClaims, localSignInProps);

            var name = externalUser.FindFirst(ClaimTypes.GivenName)?.Value;

            // issue authentication cookie for user
            var isuser = new IdentityServerUser(subjId)
            {
                DisplayName = name,
                IdentityProvider = provider,
                AdditionalClaims = additionalLocalClaims
            };

            await httpContext.SignInAsync(isuser, localSignInProps);

            // delete temporary cookie used during external authentication
            await httpContext.SignOutAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);

            // retrieve return URL
            var returnUrl = result.Properties.Items["returnUrl"] ?? "~/";           

            return Results.Redirect(returnUrl);
        });

        return group;
    }

    private static void CaptureExternalLoginContext(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
    {
        ArgumentNullException.ThrowIfNull(externalResult.Principal, nameof(externalResult.Principal));

        // capture the idp used to login, so the session knows where the user came from
        localClaims.Add(new Claim(JwtClaimTypes.IdentityProvider, externalResult.Properties?.Items["scheme"] ?? "unknown identity provider"));

        // if the external system sent a session id claim, copy it over
        // so we can use it for single sign-out
        var sid = externalResult.Principal.Claims.FirstOrDefault(x => x.Type == JwtClaimTypes.SessionId);
        if (sid != null)
        {
            localClaims.Add(new Claim(JwtClaimTypes.SessionId, sid.Value));
        }

        // if the external provider issued an id_token, we'll keep it for signout
        var idToken = externalResult.Properties?.GetTokenValue("id_token");
        if (idToken != null)
        {
            localSignInProps.StoreTokens(new[] { new AuthenticationToken { Name = "id_token", Value = idToken } });
        }
    }
}
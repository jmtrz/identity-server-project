using Duende.IdentityServer.Events;
using Duende.IdentityServer;
using Duende.IdentityServer.Services;
using identity.server.bff.v2.Extensions;
using IdentityModel;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Linq;
using System.Threading.Tasks;
using identity.server.bff.v2.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Azure;
using Microsoft.AspNetCore.Http.HttpResults;
using static Azure.Core.HttpHeader;
using System.Xml;
using Microsoft.VisualBasic;
using System.Web;
using Microsoft.AspNetCore.Http.Extensions;

namespace identity.server.bff.v2.Handlers;

public class ExternalAccountHandler
{
    public static IResult GoogleLoginAsync([FromQuery] string returnUrl, HttpContext httpContext) {
     
        //string provider, string returnUrl, 
        if (returnUrl.IsLocalUrl(httpContext.Request)) 
            return Results.BadRequest("Invalid return URL");

        var props = new AuthenticationProperties()
        {
            RedirectUri = $"/auth/external-callback",
            Items =
            {
                { "returnUrl", returnUrl },
                { "scheme", "Google" }
            }
        };

        var authSchemes = new List<string>()
        {
            "Google"
        };

        //var properties = signInManager.ConfigureExternalAuthenticationProperties(provider, redurectUrl);

        return Results.Challenge(props, authSchemes);
    }

    public static IResult GoogleLoginAsyncV2(
    [FromQuery] string returnUrl,    
    [FromServices] SignInManager<ApplicationUser> signInManager)
    {
        var authenticationProperties = signInManager.ConfigureExternalAuthenticationProperties("Google", "/auth/external-callback");
        var authSchemes = new List<string>()
        {
            "Google"
        };
      
        return Results.Challenge(authenticationProperties, authSchemes);

        #region old
        //var authenticationProperties = signInManager.ConfigureExternalAuthenticationProperties("Google", Url.Action(nameof(HandleExternalLogin)));
        ////string provider, string returnUrl, 
        //if (returnUrl.IsLocalUrl(httpContext.Request))
        //    return Results.BadRequest("Invalid return URL");

        //var props = new AuthenticationProperties()
        //{
        //    RedirectUri = $"/auth/external-callback",
        //    Items =
        //    {
        //        { "returnUrl", returnUrl },
        //        { "scheme", "Google" }
        //    }
        //};

        //var authSchemes = new List<string>()
        //{
        //    "Google"
        //};

        ////var properties = signInManager.ConfigureExternalAuthenticationProperties(provider, redurectUrl);

        //return Results.Challenge(props, authSchemes);
        #endregion
    }

    public static async Task<IResult> GoogleLoginCallBack(HttpContext httpContext, IIdentityServerInteractionService interaction, IEventService events)
    {
        var result = await httpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
        if (result.Succeeded != true)
        {
            throw new InvalidOperationException($"External Authentication error: {result.Failure}");
        }

        var externalUser = result.Principal ?? throw new InvalidOperationException("External authentication produced a  null principal");

        
        //var externalSub = Claim.Value;

        var additionalLocalClaims = new List<Claim>();
        var localSignInProps = new AuthenticationProperties();
        CaptureExternalLoginContext(result, additionalLocalClaims, localSignInProps);

        var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                             externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
                             throw new InvalidOperationException("Unknown userid");

        var provider = result.Properties.Items["scheme"] ?? throw new InvalidOperationException("Null scheme in authentiation properties");
        
        var name = externalUser.FindFirst(ClaimTypes.GivenName)?.Value;

        var subjId = externalUser.FindFirst(ClaimTypes.NameIdentifier)?.Value;

        var issuer = new IdentityServerUser(subjId)
        {
            DisplayName = name,
            IdentityProvider = provider,
            AdditionalClaims = additionalLocalClaims,
        };

        await httpContext.SignInAsync(issuer, localSignInProps);

        await httpContext.SignOutAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);

        var returnUrl = result.Properties.Items["returnUrl"] ?? "~/";

        var context = await interaction.GetAuthorizationContextAsync(returnUrl);
        //await events.RaiseAsync(new UserLoginSuccessEvent(provider, providerUserId, subjId, name, true, context?.Client.ClientId));

        return Results.Redirect(returnUrl);
    }

    public static async Task<IResult> GoogleLoginCallBackv2(HttpContext httpContext, IIdentityServerInteractionService interaction, IEventService events)
    {
        // Attempt to authenticate using the external cookie scheme
        var result = await httpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
        if (!result.Succeeded)
        {
            // Log the error and handle the failure case appropriately
            // Consider returning a user-friendly error message or redirecting to an error page
            return Results.Problem("External authentication error.");
        }

        // Ensure we have an authenticated principal
        if (result.Principal == null)
        {
            return Results.Problem("External authentication produced a null principal.");
        }

        var externalUser = result.Principal;

        // Prepare for creating a local user session
        var additionalLocalClaims = new List<Claim>();
        var localSignInProps = new AuthenticationProperties();
        CaptureExternalLoginContext(result, additionalLocalClaims, localSignInProps);

        // Extract the user identifier from the external claims
        var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
                          externalUser.FindFirst(ClaimTypes.NameIdentifier);

        if (userIdClaim == null)
        {
            return Results.Problem("Unknown user identifier.");
        }

        // Extract the provider information
        if (!result.Properties.Items.TryGetValue("scheme", out var scheme))
        {
            return Results.Problem("Provider scheme not found.");
        }

        var provider = scheme;
        // Extract additional user information
        var name = externalUser.FindFirst(ClaimTypes.GivenName)?.Value ?? "Unknown";
        var subjId = userIdClaim.Value;

        // Create a new IdentityServerUser
        var issuer = new IdentityServerUser(subjId)
        {
            DisplayName = name,
            IdentityProvider = provider,
            AdditionalClaims = additionalLocalClaims,
        };

        // Sign in the user and clear the external cookie
        await httpContext.SignInAsync(issuer, localSignInProps);

        await httpContext.SignOutAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);

        // Redirect the user to the return URL or a default route
        var returnUrl = result.Properties.Items.TryGetValue("returnUrl", out var url) ? url : "~/";

        var decodedReturnUrl = HttpUtility.UrlDecode(returnUrl);

        var context = await interaction.GetAuthorizationContextAsync(decodedReturnUrl);

        if (context != null)
        {
            var processedReturnURl = ProcessReturnUrl(httpContext.Request.GetEncodedUrl(), returnUrl!);
            //return Results.Redirect($"{context.RedirectUri}?{processedReturnURl!}");
            return Results.Redirect($"{processedReturnURl!}");
        }

        return Results.BadRequest(returnUrl);
    }

    public static async Task<IResult> GoogleLoginCallBackv3([FromServices] SignInManager<ApplicationUser> signInManager,[FromServices] UserManager<ApplicationUser> userManager , HttpContext httpContext, IIdentityServerInteractionService interaction, IEventService events)
    {
        var result = await httpContext.AuthenticateAsync(IdentityConstants.ExternalScheme);             

        var info = await signInManager.GetExternalLoginInfoAsync();         

        var externalLoginResult = await signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, isPersistent: false);

        if(!externalLoginResult.Succeeded)
        {
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            var newUser = new ApplicationUser
            {
                UserName = email,
                Email = email,
                EmailConfirmed = true,
            };

            var createResult = await userManager.CreateAsync(newUser);

            if(!createResult.Succeeded)
            {
                throw new Exception(createResult.Errors.Select(e => e.Description).Aggregate((errors, error) => $"{errors}, {error}"));
            }

            await userManager.AddLoginAsync(newUser,info);
            var newUserClaims = info.Principal.Claims.Append(new Claim("userId", newUser.Id));

            foreach (var claim in newUserClaims)
            {
                await userManager.AddClaimAsync(newUser, claim);
            }

            await signInManager.SignInAsync(newUser, isPersistent: false);
            await httpContext.SignOutAsync(IdentityConstants.ExternalScheme);
        }

        var returnUrl = result.Properties!.Items.TryGetValue("returnUrl", out var url) ? url : "http://localhost:5173/";

        var decodedReturnUrl = HttpUtility.UrlDecode(returnUrl);

        var context = await interaction.GetAuthorizationContextAsync(decodedReturnUrl);        

        if (context != null)
        {
            var processedReturnURl = ProcessReturnUrl(httpContext.Request.GetEncodedUrl(), returnUrl!);
            //return Results.Redirect($"{context.RedirectUri}?{processedReturnURl!}");
            return Results.Redirect($"{processedReturnURl!}");
        }

        return Results.Redirect(returnUrl);

        #region before
        // Attempt to authenticate using the external cookie scheme
        //var result = await httpContext.AuthenticateAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);
        //if (!result.Succeeded)
        //{
        //    // Log the error and handle the failure case appropriately
        //    // Consider returning a user-friendly error message or redirecting to an error page
        //    return Results.Problem("External authentication error.");
        //}

        //// Ensure we have an authenticated principal
        //if (result.Principal == null)
        //{
        //    return Results.Problem("External authentication produced a null principal.");
        //}

        //var externalUser = result.Principal;

        //// Prepare for creating a local user session
        //var additionalLocalClaims = new List<Claim>();
        //var localSignInProps = new AuthenticationProperties();
        //CaptureExternalLoginContext(result, additionalLocalClaims, localSignInProps);

        //// Extract the user identifier from the external claims
        //var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
        //                  externalUser.FindFirst(ClaimTypes.NameIdentifier);

        //if (userIdClaim == null)
        //{
        //    return Results.Problem("Unknown user identifier.");
        //}

        //// Extract the provider information
        //if (!result.Properties.Items.TryGetValue("scheme", out var scheme))
        //{
        //    return Results.Problem("Provider scheme not found.");
        //}

        //var provider = scheme;
        //// Extract additional user information
        //var name = externalUser.FindFirst(ClaimTypes.GivenName)?.Value ?? "Unknown";
        //var subjId = userIdClaim.Value;

        //// Create a new IdentityServerUser
        //var issuer = new IdentityServerUser(subjId)
        //{
        //    DisplayName = name,
        //    IdentityProvider = provider,
        //    AdditionalClaims = additionalLocalClaims,
        //};

        //// Sign in the user and clear the external cookie
        //await httpContext.SignInAsync(issuer, localSignInProps);

        //await httpContext.SignOutAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);

        //// Redirect the user to the return URL or a default route
        //var returnUrl = result.Properties.Items.TryGetValue("returnUrl", out var url) ? url : "~/";

        //var decodedReturnUrl = HttpUtility.UrlDecode(returnUrl);

        //var context = await interaction.GetAuthorizationContextAsync(decodedReturnUrl);

        //if (context != null)
        //{
        //    var processedReturnURl = ProcessReturnUrl(httpContext.Request.GetEncodedUrl(), returnUrl!);
        //    //return Results.Redirect($"{context.RedirectUri}?{processedReturnURl!}");
        //    return Results.Redirect($"{processedReturnURl!}");
        //}

        //return Results.BadRequest(returnUrl);
        #endregion
    }

    static void CaptureExternalLoginContext(AuthenticateResult externalResult, List<Claim> localClaims, AuthenticationProperties localSignInProps)
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

    public static string ProcessReturnUrl(string baseUrl, string returnUrl)
    {
        // Decode the returnUrl
        var decodedReturnUrl = HttpUtility.UrlDecode(returnUrl);

        // Parse the returnUrl into a Uri
        var uri = new Uri(new Uri(baseUrl), decodedReturnUrl);

        var defaultUri = new Uri(baseUrl);
        string Url = $"{defaultUri.Scheme}://{defaultUri.Host}:{defaultUri.Port}";

        // Extract the query parameters
        var queryParams = HttpUtility.ParseQueryString(uri.Query);

        // Stick them together
        var result = "";
        foreach (var key in queryParams.AllKeys)
        {
            result += $"{key}={queryParams[key]}&";
        }

        return $"{Url}{uri.AbsolutePath}?{result}";
        //return $"{result}";
    }
}

#region youtubeTutoril
//if (!result.Succeeded)
//    throw new Exception("ext AuthN Failed");

//var extUser = result.Principal;
//var sub = extUser.FindFirst(ClaimTypes.NameIdentifier)?.Value;
//var issuer = result.Properties.Items["scheme"];

//var claims = new List<Claim>
//{
//    new("sub","123"),
//    new("name", extUser.FindFirst(ClaimTypes.Name)?.Value),
//    new("role", extUser.FindFirst(ClaimTypes.Email).Value)
//};

//var ci = new ClaimsIdentity(claims, issuer, "name", "role");
//var cp = new ClaimsPrincipal(ci);

//await httpContext.SignInAsync(cp);
//await httpContext.SignOutAsync("auth-cookie");
#endregion

#region duende sample
//if (!result.Succeeded)
//{
//    throw new InvalidOperationException($"External authenticaiton error:{ result.Failure }");
//}

//var externalUser = result.Principal ?? throw new InvalidOperationException("External authentication produced a null Principal");

//var userIdClaim = externalUser.FindFirst(JwtClaimTypes.Subject) ??
//                    externalUser.FindFirst(ClaimTypes.NameIdentifier) ??
//                      throw new InvalidOperationException("Unknown Userid");

//var provider = result.Properties.Items["scheme"] ??
//                throw new InvalidOperationException("Null scheme in authentication properties");

//var providerUserId = userIdClaim.Value;

//var extUser = result.Principal;
//var user = extUser.FindFirst(ClaimTypes.NameIdentifier)?.Value;

//List<Claim> additionalLocalClaims = new();
//var localSignInProps = new AuthenticationProperties();
//ExternalContext.CaptureExternalLoginContext(result, additionalLocalClaims, localSignInProps);

//var issuer = new IdentityServerUser(user.SubjectId)
//{
//    DisplayName = user.Username,
//    IdentityProvider = provider,
//    AdditionalClaims = additionalLocalClaims
//};

//await httpContext.SignInAsync(issuer, localSignInProps);

//await httpContext.SignOutAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);

//var returnUri = result.Properties.Items["returnUrl"] ?? "~/";

//var context = await _inter

//var uru = result.Properties.Items["uru"];

#endregion

#region blog tutorial;
//var result = await httpContext.AuthenticateAsync("auth-cookie");

//if (!result.Succeeded)
//{
//    throw new Exception("Auth Failed");
//}

//if (result.Principal == null)
//{
//    throw new Exception("External Auth Error");
//}

//var claims = result.Principal.Claims.ToList();

//var userIdClaim = claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier);

//var externalUser = result.Principal ?? throw new InvalidOperationException("External Auth Produced a null Principal");

//if (userIdClaim == null)
//{
//    throw new Exception("Unknown userId");
//}

//var email = claims.FirstOrDefault(x => x.Type == ClaimTypes.NameIdentifier);
//var userName = claims.FirstOrDefault(c =>c.Type == ClaimTypes.Name);
//var externalProvider = userIdClaim.Issuer;

//var additionalLocalClaims = new List<Claim>();

//await httpContext.SignInAsync(new IdentityServerUser(userIdClaim.Value)
//{
//    DisplayName = userName?.ToString(),
//    IdentityProvider = externalProvider,
//    AdditionalClaims = new List<Claim>()
//    {
//        new Claim(ClaimTypes.Email, email.Value)
//    },
//    AuthenticationTime = DateTime.UtcNow
//});

//await httpContext.SignOutAsync(IdentityServerConstants.ExternalCookieAuthenticationScheme);

//var returnUrl = result.Properties.Items["uru"] ?? "~/";

#endregion

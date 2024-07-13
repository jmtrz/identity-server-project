using Duende.IdentityServer.EntityFramework.DbContexts;
using Duende.IdentityServer.EntityFramework.Mappers;
using Duende.IdentityServer.Models;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using identity.server.bff.v2.Handlers;
using Microsoft.AspNetCore.Identity;

using identity.server.bff.v2.Models;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Hosting;
using identity.server.bff.v2.Data;
using System.Collections.Generic;

using System;
using identity.server.bff.v2;

var builder = WebApplication.CreateBuilder(args);

#region unused code
/*
 .AddCookie("auth-cookie")
     .AddJwtBearer("dpop", options =>
    {
        //options.Authority = "https://localhost:5001";
        options.Authority = "https://localhost:7149";

        options.TokenValidationParameters.ValidateAudience = false;
        options.MapInboundClaims = false;

        options.TokenValidationParameters.ValidTypes = new[] { "at+jwt" };
    })   
 */

//.AddOAuth("Google", options =>
//{
//    //options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
//    //options.ForwardSignOut = IdentityServerConstants.DefaultCookieAuthenticationScheme;

//    options.SignInScheme = "auth-cookie";

//    options.SaveTokens = true;

//    options.Scope.Clear();
//    //options.Scope.Add("https://www.googleapis.com/auth/userinfo.email");
//    //options.Scope.Add("https://www.googleapis.com/auth/userinfo.profile");
//    options.Scope.Add("https://www.googleapis.com/auth/youtube.readonly");

//    options.AuthorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
//    options.TokenEndpoint = "https://oauth2.googleapis.com/token";

//    options.CallbackPath = "/signin-google";

//});
//builder.Services.Configure<CookiePolicyOptions>(options =>
//{
//    options.CheckConsentNeeded = context => true;
//    options.MinimumSameSitePolicy = SameSiteMode.Unspecified;
//});

#endregion

var app = builder
    .ConfigureServices()
    .ConfigurePipelineAsync();


app.Run();






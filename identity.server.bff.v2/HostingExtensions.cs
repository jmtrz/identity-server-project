using Duende.IdentityServer.EntityFramework.DbContexts;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Configuration;
using identity.server.bff.v2.Handlers;
using Microsoft.AspNetCore.Identity;
using identity.server.bff.v2.Models;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Hosting;
using identity.server.bff.v2.Data;
using Microsoft.AspNetCore.Http;
using System;

namespace identity.server.bff.v2;

internal static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        // Add services to the container.
        // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        var allowedOrigins = builder.Configuration.GetSection("Cors:AllowedOrigins").Get<string[]>();
        builder.Services.AddCors(option => option.AddPolicy("CorsPolicy", builder =>
        {
            builder.WithOrigins(allowedOrigins!)
                   .AllowAnyMethod()
                   .AllowAnyHeader()
                   .AllowCredentials();
            // // React app's origin
        }));

        //builder.Services.AddCors(options =>
        //{
        //    options.AddPolicy("allow_all",
        //        policy => { policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod(); });
        //});

        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = CookieSecurePolicy.Always;
        });

        //builder.Services.AddSameSiteCookiePolicy();

        builder.Services.AddDbContext<ApplicationDbContext>((serviceProvider, dbContextOptionsBuilder) =>
        {
            dbContextOptionsBuilder.UseSqlServer(
                serviceProvider.GetRequiredService<IConfiguration>().GetConnectionString("Identity")
            );
        });

        builder.Services.AddDbContext<ConfigurationDbContext>((serviceProvider, dbContextOptionsBuilder) =>
        {
            object value = dbContextOptionsBuilder.UseSqlServer(
                serviceProvider.GetRequiredService<IConfiguration>().GetConnectionString("Configuration"), b => b.MigrationsAssembly("identity.server.bff.v2")
            );
        });

        builder.Services.AddDbContext<PersistedGrantDbContext>((serviceProvider, dbContextOptionsBuilder) =>
        {
            dbContextOptionsBuilder.UseSqlServer(
                serviceProvider.GetRequiredService<IConfiguration>().GetConnectionString("Persisted"), b => b.MigrationsAssembly("identity.server.bff.v2")
            );
        });


        builder.Services.AddIdentity<ApplicationUser, IdentityRole>()
            .AddDefaultTokenProviders()
            .AddEntityFrameworkStores<ApplicationDbContext>();

        builder.Services.AddIdentityServer(identityServerOptions =>
        {
            identityServerOptions.Events.RaiseErrorEvents = true;
            identityServerOptions.Events.RaiseFailureEvents = true;
            identityServerOptions.Events.RaiseInformationEvents = true;
            identityServerOptions.Events.RaiseSuccessEvents = true;

            identityServerOptions.UserInteraction.LoginUrl = "/account/login";
            identityServerOptions.UserInteraction.LoginReturnUrlParameter = "returnUrl";
            identityServerOptions.UserInteraction.LogoutUrl = "/account/logout";
            identityServerOptions.UserInteraction.LogoutIdParameter = "logoutId";
        })
        .AddAspNetIdentity<ApplicationUser>()        
        .AddConfigurationStore(configurationStoreOptions =>
        {
            configurationStoreOptions.ResolveDbContextOptions = ResolveDbContextOptions;
        })
        .AddOperationalStore(operationalStoreOption =>
        {
            operationalStoreOption.ResolveDbContextOptions = ResolveDbContextOptions;
        });

        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(jwtBearerOptions =>
            {
                jwtBearerOptions.MapInboundClaims = false;
            })
            .AddLocalApi()
            .AddCookie(options =>
             {
                 options.Cookie.HttpOnly = true; // Makes the cookie inaccessible to client-side scripts
                 options.Cookie.SecurePolicy = CookieSecurePolicy.Always; // Ensures the cookie is only sent over HTTPS
                 options.ExpireTimeSpan = TimeSpan.FromMinutes(60); // Sets the cookie expiration time
                                                                    // Additional configuration...                                                                   
             })
            .AddOpenIdConnect("Google", "Sign-in with Google", options =>
            {                
                options.SignInScheme = IdentityConstants.ExternalScheme;
                //options.SignInScheme = "auth-cookie";
                //options.ForwardSignOut = IdentityServerConstants.DefaultCookieAuthenticationScheme;

                //options.Authority = "https://accounts.google.com/";


                options.ResponseType = OpenIdConnectResponseType.Code;
                options.GetClaimsFromUserInfoEndpoint = true;
                options.SaveTokens = true;

                options.CallbackPath = "/signin-google";
                options.Scope.Add("openid"); // Required for an id_token
                options.Scope.Add("profile"); // Optional, to include user profile information
                options.Scope.Add("email"); // Already included for email claim
                options.ResponseType = "code"; // Use "code" for Authorization Code flow

                //options.Events = new OpenIdConnectEvents
                //{
                //    OnTokenValidated = async context =>
                //    {
                //        // Access user claims and potentially create/link local user accounts
                //        var user = context.Principal?.Identity as ClaimsIdentity;
                //        var name = user.Claims;
                //        var email = user.FindFirstValue(ClaimTypes.Email);

                //        // Example: Persist user data in a database or session
                //        await _userService.CreateUserAsync(name, email);
                //    }
                //};
            });
            //.AddGoogle(options =>
            //{
            //    options.SignInScheme = IdentityConstants.ExternalScheme;
            //    options.ForwardSignOut = IdentityConstants.ExternalScheme;
            //    options.ClientId = "";
            //});


        return builder.Build();
    }

    public static WebApplication ConfigurePipelineAsync(this WebApplication app)
    {
        app.UseStaticFiles();

        app.UseRouting();

        //app.UseCookiePolicy(new CookiePolicyOptions
        //{
        //    HttpOnly = Microsoft.AspNetCore.CookiePolicy.HttpOnlyPolicy.Always,
        //    Secure = CookieSecurePolicy.Always,
        //    MinimumSameSitePolicy = SameSiteMode.Lax
        //});

        //app.UseCookiePolicy();

        app.UseIdentityServer();

        app.UseCors("CorsPolicy");

        app.MapFallbackToFile("index.html");

        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();

            using var scope = app.Services.CreateScope();

            //await scope.ServiceProvider.GetRequiredService<ApplicationDbContext>().Database.MigrateAsync();
            //await scope.ServiceProvider.GetRequiredService<ConfigurationDbContext>().Database.MigrateAsync();
            //await scope.ServiceProvider.GetRequiredService<PersistedGrantDbContext>().Database.MigrateAsync();

            var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();

            //if (await userManager.FindByNameAsync("thomas.clark") == null)
            //{
            //    await userManager.CreateAsync(
            //        new ApplicationUser
            //        {
            //            UserName = "thomas.clark",
            //            Email = "thomas.clark@example.com",
            //            GivenName = "Thomas",
            //            FamilyName = "Clark"
            //        }, "Pa55w0rd!");
            //}

            var configurationDbContext = scope.ServiceProvider.GetRequiredService<ConfigurationDbContext>();

            //if (!await configurationDbContext.Clients.AnyAsync())
            //{
            //    await configurationDbContext.Clients.AddRangeAsync(
            //        new Client
            //        {
            //            ClientId = "4ecc4153-daf9-4eca-8b60-818a63637a81",
            //            ClientSecrets = new List<Secret> { new("secret".Sha512()) },
            //            ClientName = "Web Application",
            //            AllowedGrantTypes = GrantTypes.Code,
            //            AllowedScopes = new List<string> { "openid", "profile", "email" },
            //            RedirectUris = new List<string> { "http://localhost:5173/" },
            //            PostLogoutRedirectUris = new List<string> { "http://localhost:5173/" }
            //        }.ToEntity());

            //    await configurationDbContext.SaveChangesAsync();
            //}

            //var result = await configurationDbContext.Clients.FindAsync(2);

            //if (result == null)
            //{
            //    await configurationDbContext.Clients.AddRangeAsync(
            //        new Client
            //        {
            //            ClientId = "web-pkce",
            //            ClientName = "Web Application PKCE",
            //            AllowedGrantTypes = GrantTypes.Code,
            //            RequireClientSecret = false,
            //            AllowedScopes = new List<string> { "openid", "profile", "email" },
            //            RedirectUris = new List<string> { "http://localhost:5173/" },
            //            PostLogoutRedirectUris = new List<string> { "http://localhost:5173/" }
            //        }.ToEntity());

            //    await configurationDbContext.SaveChangesAsync();
            //}

            //if (!await configurationDbContext.IdentityResources.AnyAsync())
            //{
            //    await configurationDbContext.IdentityResources.AddRangeAsync(
            //        new IdentityResources.OpenId().ToEntity(),
            //        new IdentityResources.Profile().ToEntity(),
            //        new IdentityResources.Email().ToEntity());

            //    await configurationDbContext.SaveChangesAsync();
            //}
        }

        app.UseHttpsRedirection();

        app.MapPost("/api/login", AccountHandler.LoginAsync);

        app.MapPost("/api/logout", AccountHandler.LogoutAsync);

        app.MapGet("/auth/google", ExternalAccountHandler.GoogleLoginAsyncV2);

        app.MapGet("/auth/external-callback", ExternalAccountHandler.GoogleLoginCallBackv3);

        return app;
    }

    static void ResolveDbContextOptions(IServiceProvider serviceProvider, DbContextOptionsBuilder dbContextOptionsBuilder)
    {
        dbContextOptionsBuilder.UseSqlServer(
            serviceProvider.GetRequiredService<IConfiguration>().GetConnectionString("IdentityServer")
        );
    }

}
using identity.server.bff.v3;
using Serilog;

namespace identity.server.bff.v4;

public static class HostingExtensions
{
    public static WebApplication ConfigureServices(this WebApplicationBuilder builder)
    {
        // Add services to the container.
        // Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
        builder.Services.AddEndpointsApiExplorer();
        builder.Services.AddSwaggerGen();

        builder.Services.AddCors(option => option.AddPolicy("CorsPolicy", builder =>
        {
            builder.WithOrigins("http://localhost:5173/", "https://localhost:7149/") // React app's origin
                   .AllowAnyMethod()
                   .AllowAnyHeader()
                   .AllowCredentials();
        }));

        builder.Host.UseSerilog((ctx, lc) => lc
            .WriteTo.Console(outputTemplate: "[{Timestamp:HH:mm:ss} {Level} {SourceContext}{NewLine}{Message:lj}{NewLine}{Exception}{NewLine}")
            .Enrich.FromLogContext()
            .ReadFrom.Configuration(ctx.Configuration));

        builder.Services.AddIdentityServer(options =>
        {
            // https://docs.duendesoftware.com/identityserver/v6/fundamentals/resources/api_scopes#authorization-based-on-scopes
            options.EmitStaticAudienceClaim = true;
        })
            .AddInMemoryIdentityResources(Config.IdentityResources)
            .AddInMemoryApiScopes(Config.ApiScopes)
            .AddInMemoryClients(Config.Clients);

        builder.Services.AddAuthentication()
                .AddCookie("auth-cookie")
                .AddOpenIdConnect("Google", options =>
                {
                    options.SignInScheme = "auth-cookie";

                    options.Authority = "https://accounts.google.com/";

                    options.CallbackPath = "/signin-google";
                    options.Scope.Add("email");
                });

        return builder.Build();
    }

    public static WebApplication ConfigurePipeline(this WebApplication app)
    {

        // Configure the HTTP request pipeline.
        if (app.Environment.IsDevelopment())
        {
            app.UseSwagger();
            app.UseSwaggerUI();
        }

        app.UseHttpsRedirection();
        // uncomment if you want to add a UI
        app.UseStaticFiles();
        app.UseRouting();

        app.UseIdentityServer();

        // uncomment if you want to add a UI
        //app.UseAuthorization();
        app.MapFallbackToFile("index.html");

        app.UseCors("CorsPolicy");

        app.MapGroup("/auth")
            .ExternalAuthGroup();

        return app;
    }
}
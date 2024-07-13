

using identity.server.bff.v4;
using Serilog;

Log.Logger = new LoggerConfiguration()
    .WriteTo.Console()
    .CreateBootstrapLogger();

Log.Information("Starting Up");

var builder = WebApplication.CreateBuilder(args);


var app = builder
    .ConfigureServices()
    .ConfigurePipeline();


app.Run();



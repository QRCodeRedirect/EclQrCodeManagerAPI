using EclQrCodeManagerAPI.Data;
using EclQrCodeManagerAPI.Interfaces;
using EclQrCodeManagerAPI.Services;
using Microsoft.EntityFrameworkCore;

var builder = WebApplication.CreateBuilder(args);

// Load Cosmos DB config
var cosmosSection = builder.Configuration.GetSection("CosmosDb");
string account = cosmosSection["Account"];
string key = cosmosSection["Key"];
string dbName = cosmosSection["DatabaseName"];

// DbContext
builder.Services.AddDbContext<AppDbContext>(options =>
    options.UseCosmos(account, key, dbName));

// Dependency Injection registrations
builder.Services.AddScoped<IUserService, UserService>();
builder.Services.AddScoped(typeof(IRepository<>), typeof(EfRepository<>));

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

var app = builder.Build();

// Swagger middleware (enabled always)
app.UseSwagger();
app.UseSwaggerUI(c =>
{
    c.SwaggerEndpoint("/swagger/v1/swagger.json", "EclQrCodeManagerAPI v1");

    // Option 1: Swagger UI at root (https://localhost:7106/)
    c.RoutePrefix = string.Empty;

    // Option 2: If you prefer Swagger at /swagger, comment out the line above
    // and access via https://localhost:7106/swagger
});

app.UseHttpsRedirection();
app.UseAuthorization();
app.MapControllers();

// Ensure Cosmos containers exist
using (var scope = app.Services.CreateScope())
{
    var ctx = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    // EF Core provider for Cosmos will create containers on first use.
    // Optionally seed data:
    // await SeedData.InitializeAsync(ctx);
}

app.Run();

using Microsoft.AspNetCore.Identity;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Scaffolding;

public static class Lab03Identity
{
    public static void AddLab03Identity(this WebApplicationBuilder builder)
    {
        builder.Services.AddIdentity<ApplicationUser, IdentityRole<Guid>>(options =>
        {
            options.User.RequireUniqueEmail = true;
            options.Password.RequiredLength = 10;
        }).AddEntityFrameworkStores<SecureLabDbContext>().AddDefaultTokenProviders();
        builder.Services.AddAuthorization();
        builder.Services.ConfigureApplicationCookie(options =>
        {
            options.Cookie.HttpOnly = true;
            options.Cookie.SameSite = SameSiteMode.Lax;
            options.Cookie.SecurePolicy = builder.Environment.IsDevelopment()
                ? CookieSecurePolicy.SameAsRequest : CookieSecurePolicy.Always;
            options.Events.OnRedirectToLogin = context =>
            {
                context.Response.StatusCode = StatusCodes.Status401Unauthorized;
                return Task.CompletedTask;
            };
            options.Events.OnRedirectToAccessDenied = context =>
            {
                context.Response.StatusCode = StatusCodes.Status403Forbidden;
                return Task.CompletedTask;
            };
        });
    }

    public static void MapLab03Identity(this WebApplication app)
    {
        app.MapPost("/api/auth/register", async (RegistrationInput input, UserManager<ApplicationUser> users) =>
        {
            // ЛР 03: завершіть DTO validation та перевірки довірчої межі.
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrWhiteSpace(input.Email)
                || string.IsNullOrWhiteSpace(input.DisplayName) || string.IsNullOrEmpty(input.Password))
                return Results.BadRequest();
            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(), UserName = input.UserName.Trim(), Email = input.Email.Trim(),
                DisplayName = input.DisplayName.Trim()
            };
            var result = await users.CreateAsync(user, input.Password);
            if (!result.Succeeded) return Results.BadRequest(new { message = "Registration failed" });
            var role = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
            if (!role.Succeeded) throw new InvalidOperationException("Default role assignment failed.");
            return Results.Created("/api/me", new { user.Id, user.UserName, user.DisplayName });
        });
        app.MapPost("/api/auth/login", async (LoginInput input, SignInManager<ApplicationUser> signIn) =>
        {
            if (string.IsNullOrWhiteSpace(input.UserName) || string.IsNullOrEmpty(input.Password))
                return Results.Unauthorized();
            var result = await signIn.PasswordSignInAsync(input.UserName, input.Password, false, false);
            return result.Succeeded ? Results.NoContent() : Results.Unauthorized();
        });
        app.MapPost("/api/auth/logout", () => Results.StatusCode(StatusCodes.Status501NotImplemented));
        // Навмисно хибна навчальна довіра: ЛР 03 замінює заявлений id на verified principal.
        app.MapGet("/api/me", async (HttpContext context, SecureLabDbContext db) =>
        {
            if (!Guid.TryParse(context.Request.Headers["X-Demo-UserId"], out var claimedId))
                return Results.StatusCode(StatusCodes.Status501NotImplemented);
            var user = await db.Users.FindAsync(claimedId);
            return user is null ? Results.NotFound() : Results.Ok(new { user.Id, user.UserName, user.DisplayName });
        });
        // Приклад лише mechanics: не повертає identity і не реалізує оцінювану operation.
        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }
}

public sealed record RegistrationInput(string? UserName, string? Email, string? DisplayName, string? Password);
public sealed record LoginInput(string? UserName, string? Password);

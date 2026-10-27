using Microsoft.AspNetCore.Identity;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;
using System.Net.Mail;
using System.Security.Claims;
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
            // Одна безпечна відмова для будь-якої невдалої реєстрації.
            var failed = Results.BadRequest(new { message = "Registration failed" });

            if (!IsValidRegistration(input))
                return failed;

            var user = new ApplicationUser
            {
                Id = Guid.NewGuid(),
                UserName = input.UserName!.Trim(),
                Email = input.Email!.Trim(),
                DisplayName = input.DisplayName!.Trim()
            };

            // PasswordHash обчислює Identity; власного хешування немає.
            var result = await users.CreateAsync(user, input.Password!);
            if (!result.Succeeded)
                return failed;

            var role = await users.AddToRoleAsync(user, DbSeeder.ReporterRole);
            if (!role.Succeeded) throw new InvalidOperationException("Default role assignment failed.");

            return Results.Created("/api/me",
                new RegistrationResponse(user.Id, user.UserName!, user.DisplayName));
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
        app.MapGet("/api/me", GetCurrentUser).RequireAuthorization();
        // Приклад лише mechanics: не повертає identity і не реалізує оцінювану operation.
        app.MapGet("/api/auth/session-check", () => Results.NoContent()).RequireAuthorization();
    }
    private static bool IsValidRegistration(RegistrationInput input)
    {
        var userName = input.UserName?.Trim();
        var email = input.Email?.Trim();
        var displayName = input.DisplayName?.Trim();
        var password = input.Password;

        if (string.IsNullOrEmpty(userName) || userName.Length > 256) return false;
        if (string.IsNullOrEmpty(displayName) || displayName.Length > 120) return false;
        if (string.IsNullOrEmpty(email) || email.Length > 256) return false;

        if (!MailAddress.TryCreate(email, out var parsed) || parsed.Address != email)
            return false;

        if (string.IsNullOrEmpty(password) || password.Length > 128) return false;

        return true;
    }
    private static IResult GetCurrentUser(HttpContext httpContext)
    {
        
        var userId = httpContext.User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        if (!Guid.TryParse(userId, out var verifiedUserId))
        {
            return Results.Problem(statusCode: StatusCodes.Status500InternalServerError);
        }

        var userName = httpContext.User.FindFirst(ClaimTypes.Name)?.Value ?? string.Empty;
        var role = httpContext.User.FindFirst(ClaimTypes.Role)?.Value ?? string.Empty;

        return Results.Ok(new MeResponse(verifiedUserId, userName, role));
    }
}

public sealed record RegistrationInput(string? UserName, string? Email, string? DisplayName, string? Password);
public sealed record LoginInput(string? UserName, string? Password);
public sealed record RegistrationResponse(Guid Id, string UserName, string DisplayName);
public sealed record MeResponse(Guid UserId, string UserName, string Role);
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Data;

public static class DatabaseBootstrap
{
    public static async Task InitializeAsync(
        IServiceProvider services,
        IConfiguration configuration,
        IHostEnvironment environment,
        bool resetRequested)
    {
        await using var scope = services.CreateAsyncScope();
        var dbContext = scope.ServiceProvider.GetRequiredService<SecureLabDbContext>();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<IdentityRole<Guid>>>();

        if (resetRequested)
        {
            var resetAllowed = configuration.GetValue<bool>("Database:AllowReset");
            if (!environment.IsDevelopment() || !resetAllowed)
            {
                throw new InvalidOperationException(
                    "Reset даних дозволено лише в явно налаштованому Development environment.");
            }

            Console.WriteLine("Відновлення початкових локальних навчальних даних...");
            await dbContext.Database.MigrateAsync();
            // The table names are fixed by the model and never assembled from input.
            // CASCADE clears only the explicitly selected local study schema.
            await dbContext.Database.ExecuteSqlRawAsync(
                "TRUNCATE TABLE incident_comments, incident_status_history, incidents, "
                + "identity_user_tokens, identity_user_roles, identity_user_logins, "
                + "identity_user_claims, identity_role_claims, identity_users, identity_roles "
                + "RESTART IDENTITY CASCADE;");
            await DbSeeder.SeedAsync(dbContext, userManager, roleManager, configuration);
        await SecureLab.Api.Scaffolding.Lab02Seed.EnsureAsync(services);
            Console.WriteLine("Локальні навчальні дані очищено та повторно заповнено seed-значеннями.");
            return;
        }

        if (!configuration.GetValue<bool>("Database:ApplyMigrationsOnStartup"))
        {
            return;
        }

        await dbContext.Database.MigrateAsync();
        await DbSeeder.SeedAsync(dbContext, userManager, roleManager, configuration);
        await SecureLab.Api.Scaffolding.Lab02Seed.EnsureAsync(services);
    }
}

using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Data;

public static class DbSeeder
{
    public const string ReporterRole = "Reporter";
    public const string AnalystRole = "Analyst";
    public const string AdministratorRole = "Administrator";

    public static readonly Guid AliceId = Guid.Parse("10000000-0000-0000-0000-000000000001");
    public static readonly Guid BobId = Guid.Parse("10000000-0000-0000-0000-000000000002");
    public static readonly Guid MorganId = Guid.Parse("10000000-0000-0000-0000-000000000003");
    public static readonly Guid AdminId = Guid.Parse("10000000-0000-0000-0000-000000000004");

    public static readonly Guid AliceIncidentId = Guid.Parse("20000000-0000-0000-0000-000000000001");
    public static readonly Guid BobIncidentId = Guid.Parse("20000000-0000-0000-0000-000000000002");
    public static readonly Guid SafeTextIncidentId = Guid.Parse("20000000-0000-0000-0000-000000000003");

    private static readonly Guid ReporterRoleId =
        Guid.Parse("50000000-0000-0000-0000-000000000001");
    private static readonly Guid AnalystRoleId =
        Guid.Parse("50000000-0000-0000-0000-000000000002");
    private static readonly Guid AdministratorRoleId =
        Guid.Parse("50000000-0000-0000-0000-000000000003");

    public static async Task SeedAsync(
        SecureLabDbContext dbContext,
        UserManager<ApplicationUser> userManager,
        RoleManager<IdentityRole<Guid>> roleManager,
        IConfiguration configuration)
    {
        await EnsureRoleAsync(roleManager, ReporterRoleId, ReporterRole);
        await EnsureRoleAsync(roleManager, AnalystRoleId, AnalystRole);
        await EnsureRoleAsync(roleManager, AdministratorRoleId, AdministratorRole);

        var password = configuration["SeedUsers:Password"];
        var userCount = await dbContext.Users.CountAsync(user =>
            user.Id == AliceId || user.Id == BobId || user.Id == MorganId || user.Id == AdminId);
        if ((userCount < 4 || await dbContext.Users.AnyAsync(user => user.PasswordHash == null)) && string.IsNullOrWhiteSpace(password))
        {
            throw new InvalidOperationException(
                "SeedUsers:Password має бути передано поза Git для створення локальних навчальних акаунтів.");
        }

        var alice = await EnsureUserAsync(
            userManager, AliceId, "alice", "alice@example.test", "Аліса Коваль", ReporterRole, password);
        var bob = await EnsureUserAsync(
            userManager, BobId, "bob", "bob@example.test", "Боб Мельник", ReporterRole, password);
        var morgan = await EnsureUserAsync(
            userManager, MorganId, "morgan", "morgan@example.test", "Морган Литвин", AnalystRole, password);
        _ = await EnsureUserAsync(
            userManager, AdminId, "admin", "admin@example.test", "Локальний адміністратор", AdministratorRole, password);

        if (await dbContext.Incidents.AnyAsync())
        {
            return;
        }

        var aliceIncident = new Incident
        {
            Id = AliceIncidentId,
            Owner = alice,
            Title = "Підозрілий лист із вкладенням",
            Description = "Одержано лист нібито від деканату. Вкладення не відкривалося.",
            Severity = IncidentSeverity.Medium,
            Status = IncidentStatus.Triaged,
            OccurredAtUtc = new DateTimeOffset(2026, 8, 1, 8, 30, 0, TimeSpan.Zero),
            CreatedAtUtc = new DateTimeOffset(2026, 8, 1, 9, 0, 0, TimeSpan.Zero),
            UpdatedAtUtc = new DateTimeOffset(2026, 8, 1, 10, 0, 0, TimeSpan.Zero)
        };
        var bobIncident = new Incident
        {
            Id = BobIncidentId,
            Owner = bob,
            Title = "Невідома спроба входу",
            Description = "Система зафіксувала вхід до облікового запису з нового пристрою.",
            Severity = IncidentSeverity.High,
            Status = IncidentStatus.InProgress,
            OccurredAtUtc = new DateTimeOffset(2026, 8, 2, 14, 10, 0, TimeSpan.Zero),
            CreatedAtUtc = new DateTimeOffset(2026, 8, 2, 14, 20, 0, TimeSpan.Zero),
            UpdatedAtUtc = new DateTimeOffset(2026, 8, 2, 15, 0, 0, TimeSpan.Zero)
        };
        var safeTextIncident = new Incident
        {
            Id = Guid.Parse("20000000-0000-0000-0000-000000000003"),
            Owner = alice,
            Title = "Перевірка журналу комп'ютерного класу",
            Description = "Текст <script> має відображатися як текст, а не виконуватися як HTML.",
            Severity = IncidentSeverity.Low,
            Status = IncidentStatus.New,
            OccurredAtUtc = new DateTimeOffset(2026, 8, 3, 7, 45, 0, TimeSpan.Zero),
            CreatedAtUtc = new DateTimeOffset(2026, 8, 3, 8, 0, 0, TimeSpan.Zero),
            UpdatedAtUtc = new DateTimeOffset(2026, 8, 3, 8, 0, 0, TimeSpan.Zero)
        };

        dbContext.Incidents.AddRange(aliceIncident, bobIncident, safeTextIncident);
        dbContext.IncidentComments.AddRange(
            new IncidentComment
            {
                Id = Guid.Parse("30000000-0000-0000-0000-000000000001"),
                Incident = aliceIncident,
                Author = morgan,
                Text = "Заголовки листа передано аналітику.",
                IsInternal = false,
                CreatedAtUtc = new DateTimeOffset(2026, 8, 1, 9, 30, 0, TimeSpan.Zero)
            },
            new IncidentComment
            {
                Id = Guid.Parse("30000000-0000-0000-0000-000000000002"),
                Incident = bobIncident,
                Author = morgan,
                Text = "Розпочато перевірку журналу автентифікації.",
                IsInternal = false,
                CreatedAtUtc = new DateTimeOffset(2026, 8, 2, 14, 40, 0, TimeSpan.Zero)
            });
        dbContext.IncidentStatusHistory.Add(
            new IncidentStatusHistory
            {
                Id = Guid.Parse("40000000-0000-0000-0000-000000000001"),
                Incident = aliceIncident,
                ChangedByUser = morgan,
                OldStatus = IncidentStatus.New,
                NewStatus = IncidentStatus.Triaged,
                Note = "Первинну оцінку завершено.",
                CreatedAtUtc = new DateTimeOffset(2026, 8, 1, 10, 0, 0, TimeSpan.Zero)
            });

        await dbContext.SaveChangesAsync();
    }

    private static async Task EnsureRoleAsync(
        RoleManager<IdentityRole<Guid>> roleManager,
        Guid id,
        string name)
    {
        if (await roleManager.RoleExistsAsync(name))
        {
            return;
        }

        var result = await roleManager.CreateAsync(new IdentityRole<Guid>
        {
            Id = id,
            Name = name
        });
        EnsureSucceeded(result, $"create role {name}");
    }

    private static async Task<ApplicationUser> EnsureUserAsync(
        UserManager<ApplicationUser> userManager,
        Guid id,
        string userName,
        string email,
        string displayName,
        string role,
        string? password)
    {
        var existing = await userManager.FindByIdAsync(id.ToString());
        if (existing is not null)
        {
            if (!await userManager.HasPasswordAsync(existing))
            {
                EnsureSucceeded(await userManager.AddPasswordAsync(existing,
                    password ?? throw new InvalidOperationException("Seed password is missing.")), "set study password");
                await userManager.UpdateSecurityStampAsync(existing);
            }
            if (!await userManager.IsInRoleAsync(existing, role))
                EnsureSucceeded(await userManager.AddToRoleAsync(existing, role), "assign study role");
            return existing;
        }

        var user = new ApplicationUser
        {
            Id = id,
            UserName = userName,
            Email = email,
            DisplayName = displayName,
            EmailConfirmed = true
        };
        var createResult = await userManager.CreateAsync(
            user,
            password ?? throw new InvalidOperationException("Seed password is missing."));
        EnsureSucceeded(createResult, $"create user {userName}");
        EnsureSucceeded(await userManager.AddToRoleAsync(user, role), $"assign role {role}");
        return user;
    }

    private static void EnsureSucceeded(IdentityResult result, string operation)
    {
        if (result.Succeeded)
        {
            return;
        }

        var codes = string.Join(", ", result.Errors.Select(error => error.Code));
        throw new InvalidOperationException($"Identity seed operation '{operation}' failed: {codes}.");
    }
}

using System.Diagnostics;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using SecureLab.Api.Application.Incidents;
using SecureLab.Api.Data;                    // SecureLabDbContext
using SecureLab.Api.Data.Entities;           // IncidentStatus
using SecureLab.Api.Presentation.Contracts;  // IncidentCommentResponse

namespace SecureLab.Api.Presentation.Endpoints;

/// <summary>
/// Контракт звичайного content update. Навмисно НЕ містить OwnerUserId,
/// Status, Severity, Role, Id і службових дат: їх визначає лише сервер (A-08a).
/// </summary>
public sealed record UpdateIncidentRequest(
    string Title,
    string Description,
    DateTimeOffset? OccurredAtUtc);

/// <summary>Однакові відповіді відмов для всього perimeter Incident (політика 404).</summary>
public static class IncidentResults
{
    // Один helper для чужого і неіснуючого id: без detail з id (A-10).
    public static IResult NotFound() => Results.Problem(
        title: "Інцидент не знайдено",
        statusCode: StatusCodes.Status404NotFound);

    public static IResult Forbidden() => Results.Problem(
        title: "Дію заборонено",
        statusCode: StatusCodes.Status403Forbidden);

    public static IResult Conflict() => Results.Problem(
        title: "Дія недоступна для поточного статусу",
        statusCode: StatusCodes.Status409Conflict);
}

/// <summary>
/// ЛР 4, FIXED STATE (крок 6, 11, 12).
/// Порядок: 401 (група) → tracked entity → видимість (404) → право на дію (403)
/// → допустимість стану (409) → зміна → SaveChanges.
/// </summary>
public static class IncidentMutationEndpoints
{
    public static IEndpointRouteBuilder MapIncidentMutationEndpoints(
        this IEndpointRouteBuilder app)
    {
        var incidents = app.MapGroup("/api/incidents").RequireAuthorization();
        incidents.MapPut("/{id:guid}", UpdateAsync);
        incidents.MapDelete("/{id:guid}", DeleteAsync);
        incidents.MapPost("/{id:guid}/triage", TriageAsync);

        app.MapGet("/api/incident-comments/{id:guid}", GetCommentAsync)
            .RequireAuthorization();

        return app;
    }

    // Owner — 204; чужий/неіснуючий — 404; Analyst (бачить, але не редагує) — 403.
    private static async Task<IResult> UpdateAsync(
        Guid id,
        UpdateIncidentRequest request,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents                       // tracked
            .SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentResults.NotFound();
        }

        var canRead = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Read);
        if (!canRead.Succeeded)
        {
            return IncidentResults.NotFound();                         // як неіснуючий
        }

        var canUpdate = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Update);
        if (!canUpdate.Succeeded)
        {
            return IncidentResults.Forbidden();
        }

        if (string.IsNullOrWhiteSpace(request.Title)
            || string.IsNullOrWhiteSpace(request.Description))
        {
            return Results.ValidationProblem(new Dictionary<string, string[]>
            {
                ["title"] = ["Title і description обов'язкові."]
            });
        }

        // Зміна лише після обох дозволів і лише дозволених content-полів.
        incident.Title = request.Title.Trim();
        incident.Description = request.Description.Trim();
        if (request.OccurredAtUtc is { } occurred)
        {
            incident.OccurredAtUtc = occurred.ToUniversalTime();
        }

        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    // Owner і status New — 204; owner, але не New — 409; чужий — 404; Analyst — 403.
    private static async Task<IResult> DeleteAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        var incident = await dbContext.Incidents
            .SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentResults.NotFound();
        }

        var canRead = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Read);
        if (!canRead.Succeeded)
        {
            return IncidentResults.NotFound();
        }

        var canDelete = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Delete);
        if (!canDelete.Succeeded)
        {
            return IncidentResults.Forbidden();
        }

        if (incident.Status != IncidentStatus.New)
        {
            return IncidentResults.Conflict();
        }

        dbContext.Incidents.Remove(incident);
        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    // Privileged transition: роль перевіряється ДО пошуку ресурсу (403 не розкриває існування).
    // Рішення ухвалюється всередині endpoint, щоб записати audit event при deny.
    private static async Task<IResult> TriageAsync(
        Guid id,
        HttpContext httpContext,
        IAuthorizationService authorizationService,
        SecureLabDbContext dbContext,
        ILoggerFactory loggerFactory,
        CancellationToken cancellationToken)
    {
        var roleDecision = await authorizationService.AuthorizeAsync(
            httpContext.User, IncidentPolicies.Triage);
        if (!roleDecision.Succeeded)
        {
            AuditDenied(loggerFactory, httpContext, "incident.triage", id);
            return IncidentResults.Forbidden();
        }

        var incident = await dbContext.Incidents                       // tracked
            .SingleOrDefaultAsync(x => x.Id == id, cancellationToken);
        if (incident is null)
        {
            return IncidentResults.NotFound();
        }

        var canRead = await authorizationService.AuthorizeAsync(
            httpContext.User, incident, IncidentOperations.Read);
        if (!canRead.Succeeded)
        {
            return IncidentResults.NotFound();
        }

        // Поточний статус — з БД; наступний визначає сервер. Body не приймається.
        if (incident.Status != IncidentStatus.New)
        {
            return IncidentResults.Conflict();
        }

        incident.Status = IncidentStatus.Triaged;
        await dbContext.SaveChangesAsync(cancellationToken);
        return Results.NoContent();
    }

    // Child через parent: те саме правило видимості інциденту + internal лише для Analyst.
    private static async Task<IResult> GetCommentAsync(
        Guid id,
        HttpContext httpContext,
        SecureLabDbContext dbContext,
        CancellationToken cancellationToken)
    {
        if (!CurrentUser.TryGetId(httpContext.User, out var userId))
        {
            return Results.Challenge();
        }

        var isAnalyst = CurrentUser.IsAnalyst(httpContext.User);

        var comment = await dbContext.Incidents
            .AsNoTracking()
            .Where(IncidentAccessRules.VisibleTo(userId, isAnalyst))
            .SelectMany(incident => incident.Comments)
            .Where(comment => comment.Id == id && (isAnalyst || !comment.IsInternal))
            .Select(comment => new IncidentCommentResponse(
                comment.Id,
                comment.Author.DisplayName,
                comment.Text,
                comment.CreatedAtUtc))
            .SingleOrDefaultAsync(cancellationToken);

        return comment is null ? IncidentResults.NotFound() : Results.Ok(comment);
    }

    // Безпечна audit-подія: без cookie, password, token, body і stack trace.
    // traceId — той самий, що ASP.NET Core пише в Problem Details відповіді.
    private static void AuditDenied(
        ILoggerFactory loggerFactory, HttpContext httpContext, string action, Guid resourceId)
    {
        var logger = loggerFactory.CreateLogger("SecureLab.Audit");
        logger.LogWarning(
            "authorization.denied subject={SubjectId} action={Action} "
            + "resource={ResourceId} result={Result} "
            + "occurredAtUtc={OccurredAtUtc:O} traceId={TraceId}",
            httpContext.User.FindFirstValue(ClaimTypes.NameIdentifier),
            action,
            resourceId,
            "denied",
            DateTimeOffset.UtcNow,
            Activity.Current?.Id ?? httpContext.TraceIdentifier);
    }
}

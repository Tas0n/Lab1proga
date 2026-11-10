using System.Linq.Expressions;
using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Authorization.Infrastructure;
using SecureLab.Api.Data;
using SecureLab.Api.Data.Entities;

namespace SecureLab.Api.Application.Incidents;

/// <summary>Операції над Incident, для яких ухвалюється ресурсне рішення.</summary>
public static class IncidentOperations
{
    public static readonly OperationAuthorizationRequirement Read = new() { Name = nameof(Read) };
    public static readonly OperationAuthorizationRequirement Update = new() { Name = nameof(Update) };
    public static readonly OperationAuthorizationRequirement Delete = new() { Name = nameof(Delete) };
}

/// <summary>Назви policy для привілейованих дій.</summary>
public static class IncidentPolicies
{
    /// <summary>POST /api/incidents/{id}/triage: лише роль Analyst.</summary>
    public const string Triage = "IncidentTriage";
}

/// <summary>Єдине джерело identity: лише перевірений principal, не body/URL/header.</summary>
public static class CurrentUser
{
    public static bool TryGetId(ClaimsPrincipal user, out Guid userId) =>
        Guid.TryParse(user.FindFirstValue(ClaimTypes.NameIdentifier), out userId);

    public static bool IsAnalyst(ClaimsPrincipal user) =>
        user.IsInRole(DbSeeder.AnalystRole);
}

/// <summary>
/// Правило видимості з docs/access-matrix.md в одному місці.
/// Reporter і Administrator бачать лише власні інциденти; Analyst — усі.
/// Використовується і в EF-запитах (query scoping), і в handler.
/// </summary>
public static class IncidentAccessRules
{
    public static Expression<Func<Incident, bool>> VisibleTo(Guid userId, bool isAnalyst) =>
        incident => isAnalyst || incident.OwnerUserId == userId;

    public static bool CanRead(Incident incident, Guid userId, bool isAnalyst) =>
        VisibleTo(userId, isAnalyst).Compile()(incident);

    /// <summary>Content update і delete: лише власник; Analyst — ні (лише читання і triage).</summary>
    public static bool CanModify(Incident incident, Guid userId, bool isAnalyst) =>
        !isAnalyst && incident.OwnerUserId == userId;
}

/// <summary>
/// Resource-based handler: principal + завантажений Incident + операція.
/// Не викликав Succeed — відмова.
/// </summary>
public sealed class IncidentAuthorizationHandler
    : AuthorizationHandler<OperationAuthorizationRequirement, Incident>
{
    protected override Task HandleRequirementAsync(
        AuthorizationHandlerContext context,
        OperationAuthorizationRequirement requirement,
        Incident incident)
    {
        if (!CurrentUser.TryGetId(context.User, out var userId))
        {
            return Task.CompletedTask;
        }

        var isAnalyst = CurrentUser.IsAnalyst(context.User);

        var allowed = requirement.Name switch
        {
            nameof(IncidentOperations.Read) =>
                IncidentAccessRules.CanRead(incident, userId, isAnalyst),
            nameof(IncidentOperations.Update) =>
                IncidentAccessRules.CanModify(incident, userId, isAnalyst),
            nameof(IncidentOperations.Delete) =>
                IncidentAccessRules.CanModify(incident, userId, isAnalyst),
            _ => false
        };

        if (allowed)
        {
            context.Succeed(requirement);
        }

        return Task.CompletedTask;
    }
}

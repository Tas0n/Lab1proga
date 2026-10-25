using Microsoft.AspNetCore.Identity;

namespace SecureLab.Api.Data.Entities;

public sealed class ApplicationUser : IdentityUser<Guid>
{
    public required string DisplayName { get; set; }
    public List<Incident> Incidents { get; set; } = [];
}

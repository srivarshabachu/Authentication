using Microsoft.AspNetCore.Identity;


namespace User.Management.Data.Models
{
    public class ApplicationUser:IdentityUser
    {
        public string? RefreshToken { get; set; } = null!;
        public DateTime? RefreshTokenExpiry { get; set; }
    }
}

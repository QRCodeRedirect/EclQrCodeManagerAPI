using EclQrCodeManagerAPI.Entities;
using Microsoft.EntityFrameworkCore;

namespace EclQrCodeManagerAPI.Data
{
    public static class SeedData
    {
        public static async Task InitializeAsync(AppDbContext db)
        {
            if (await db.Users.AnyAsync()) return;
            db.Users.Add(new User
            {
                UserID = 1,
                Username = "Alice",
                PasswordHash = "hashedpassword1",
                Email = "alice@example.com",
                Role = "Admin",
                CreatedDate = DateTime.UtcNow,
                LastLoginDate = DateTime.UtcNow.AddDays(-1),
                Status = true,
                Division = "IT",
                BusinessUnit = "Development",
                SSO_Provider_ID = "sso1",
                SSO_Provider = "Azure"
            });
            db.Users.Add(new User
            {
                UserID = 2,
                Username = "Bob",
                PasswordHash = "hashedpassword2",
                Email = "bob@example.com",
                Role = "User",
                CreatedDate = DateTime.UtcNow,
                LastLoginDate = null,
                Status = true,
                Division = "HR",
                BusinessUnit = "Operations",
                SSO_Provider_ID = "sso2",
                SSO_Provider = "Microsoft"
            });
            await db.SaveChangesAsync();
        }
    }
}

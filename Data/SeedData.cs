using EclQrCodeManagerAPI.Entities;
using Microsoft.EntityFrameworkCore;

namespace EclQrCodeManagerAPI.Data
{
    public static class SeedData
    {
        public static async Task InitializeAsync(AppDbContext db)
        {
            if (await db.Users.AnyAsync()) return;
            db.Users.Add(new User { Email = "alice@example.com", FullName = "Alice" });
            db.Users.Add(new User { Email = "bob@example.com", FullName = "Bob" });
            await db.SaveChangesAsync();
        }
    }
}

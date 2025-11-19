using EclQrCodeManagerAPI.Entities;
using Microsoft.EntityFrameworkCore;

namespace EclQrCodeManagerAPI.Data
{
    public class AppDbContext : DbContext
    {
        public DbSet<User> Users { get; set; } = null!;

        public AppDbContext(DbContextOptions<AppDbContext> options)
            : base(options) { }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            base.OnModelCreating(modelBuilder);

            // Cosmos DB specific configuration
            if (Database.ProviderName == "Microsoft.EntityFrameworkCore.Cosmos")
            {
                modelBuilder.Entity<User>(entity =>
                {
                    entity.ToContainer("Users"); // container name
                    entity.HasPartitionKey(u => u.Email); // partition key property

                    // Configure new fields for Cosmos DB
                    entity.Property(u => u.VerificationToken).HasMaxLength(100);
                    entity.Property(u => u.ResetToken).HasMaxLength(100);
                });
            }
        }
    }
}

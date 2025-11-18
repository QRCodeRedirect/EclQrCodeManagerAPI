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
            modelBuilder.Entity<User>(entity =>
            {
                entity.ToContainer("Users");                 // container name
                entity.HasPartitionKey(u => u.Email);       // partition key property
                entity.HasKey(u => u.Id);
            });

        }

    }

}
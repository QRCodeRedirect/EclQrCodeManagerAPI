using System;
using System.ComponentModel.DataAnnotations;

namespace EclQrCodeManagerAPI.Entities
{
    public class User
    {
        [Key]
        public string Id { get; set; } = Guid.NewGuid().ToString();

        [Required]
        public string? Email { get; set; } = string.Empty;    // used as partition key

        public string? FullName { get; set; } = string.Empty;

        public string? PasswordHash { get; set; } = string.Empty;

        public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    }
}


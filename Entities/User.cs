using System;
using System.ComponentModel.DataAnnotations;

namespace EclQrCodeManagerAPI.Entities
{
    public class User
    {
        [Key]
        public int UserID { get; set; } // Primary Key

        public string? Username { get; set; }

        public string? PasswordHash { get; set; }

        [Required]
        public string? Email { get; set; } // Partition Key

        public string? Role { get; set; }

        public DateTime CreatedDate { get; set; }

        public DateTime? LastLoginDate { get; set; }

        public bool Status { get; set; } // true = active, false = inactive

        public string? Division { get; set; }

        public string? BusinessUnit { get; set; }

        public string? SSO_Provider_ID { get; set; }

        public string? SSO_Provider { get; set; }

        // New fields for secure registration and login
        public string? VerificationToken { get; set; }
        public DateTime? VerificationTokenExpiry { get; set; }
        public string? ResetToken { get; set; }
        public DateTime? ResetTokenExpiry { get; set; }
        public int FailedLoginAttempts { get; set; }
        public DateTime? LockoutEndTime { get; set; }
    }
}


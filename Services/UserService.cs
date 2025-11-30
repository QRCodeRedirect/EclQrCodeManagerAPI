using System.Collections.Generic;
using System.Threading.Tasks;
using EclQrCodeManagerAPI.Entities;
using EclQrCodeManagerAPI.Interfaces;
using EclQrCodeManagerAPI.Data;
using Microsoft.EntityFrameworkCore;
using System.Text.RegularExpressions;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using MailKit.Net.Smtp;
using MimeKit;
using System.Net.Mail;
using Microsoft.Extensions.Configuration;

namespace EclQrCodeManagerAPI.Services
{
    public class UserService : IUserService
    {
        private readonly AppDbContext _db;
        private readonly IConfiguration _config;

        public UserService(AppDbContext db, IConfiguration config)
        {
            _db = db;
            _config = config;
        }

        public async Task<User> CreateAsync(User user)
        {
            await _db.Users.AddAsync(user);
            await _db.SaveChangesAsync();
            return user;
        }

        public async Task DeleteAsync(int id)
        {
            var user = await _db.Users.FindAsync(id);
            if (user == null) return;
            _db.Users.Remove(user);
            await _db.SaveChangesAsync();
        }

        public async Task<IEnumerable<User>> GetAllAsync() => await _db.Users.ToListAsync();

        public async Task<User?> GetByIdAsync(int id) => await _db.Users.FindAsync(id);

        public async Task UpdateAsync(User user)
        {
            _db.Users.Update(user);
            await _db.SaveChangesAsync();
        }

        // New implementation for secure registration and login

        public async Task<(bool Success, string Message)> RegisterAsync(string email, string password, string name, string division, string businessUnit)
        {
            // Validate email format
            if (!IsValidEmail(email))
                return (false, "Invalid email format.");

            // Check if email already exists
            var existingUser = await _db.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (existingUser != null)
                return (false, "Email already registered.");

            // Validate password strength
            if (!IsValidPassword(password))
                return (false, "Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.");

            // Validate required fields
            if (string.IsNullOrWhiteSpace(name) || string.IsNullOrWhiteSpace(division) || string.IsNullOrWhiteSpace(businessUnit))
                return (false, "Name, division, and business unit are required.");

            // Hash password
            var passwordHash = BCrypt.Net.BCrypt.HashPassword(password, 12);

            // Generate verification token
            var verificationToken = GenerateToken();
            var tokenExpiry = DateTime.UtcNow.AddHours(1);

            var user = new User
            {
                Email = email,
                PasswordHash = passwordHash,
                Username = name,
                Division = division,
                BusinessUnit = businessUnit,
                Status = false, // inactive until verified
                CreatedDate = DateTime.UtcNow,
                VerificationToken = verificationToken,
                VerificationTokenExpiry = tokenExpiry,
                FailedLoginAttempts = 0
            };

            await CreateAsync(user);

            // Send verification email
            await SendVerificationEmail(email, verificationToken);

            return (true, "Registration successful. Please check your email to verify your account.");
        }

        public async Task<(bool Success, string Message)> VerifyEmailAsync(string token)
        {
            var user = await _db.Users.FirstOrDefaultAsync(u => u.VerificationToken == token);
            if (user == null)
                return (false, "Invalid verification token.");

            if (user.VerificationTokenExpiry < DateTime.UtcNow)
                return (false, "Verification token has expired.");

            user.Status = true; // activate account
            user.VerificationToken = null;
            user.VerificationTokenExpiry = null;

            await UpdateAsync(user);

            return (true, "Email verified successfully. You can now log in.");
        }

        public async Task<(bool Success, string Message, string? Token, User? User)> LoginAsync(string email, string password)
        {
            var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
                return (false, "Invalid email or password.", null, null);

            // Check if account is locked
            if (user.LockoutEndTime.HasValue && user.LockoutEndTime > DateTime.UtcNow)
                return (false, "Account is locked due to too many failed attempts. Try again later.", null, null);

            // Check if account is active
            if (!user.Status)
                return (false, "Account is not verified. Please verify your email first.", null, null);

            // Verify password
            if (!BCrypt.Net.BCrypt.Verify(password, user.PasswordHash))
            {
                user.FailedLoginAttempts++;
                if (user.FailedLoginAttempts >= 5)
                {
                    user.LockoutEndTime = DateTime.UtcNow.AddMinutes(15);
                    await UpdateAsync(user);
                    return (false, "Account locked due to too many failed attempts.", null, null);
                }
                await UpdateAsync(user);
                return (false, "Invalid email or password.", null, null);
            }

            // Reset failed attempts on successful login
            user.FailedLoginAttempts = 0;
            user.LockoutEndTime = null;
            user.LastLoginDate = DateTime.UtcNow;
            await UpdateAsync(user);

            // Generate JWT
            var jwtToken = GenerateJwtToken(user);

            return (true, "Login successful.", jwtToken, user);
        }

        public async Task<(bool Success, string Message)> RequestPasswordResetAsync(string email)
        {
            var user = await _db.Users.FirstOrDefaultAsync(u => u.Email == email);
            if (user == null)
                return (false, "If an account with this email exists, a reset link has been sent.");

            var resetToken = GenerateToken();
            var tokenExpiry = DateTime.UtcNow.AddHours(1);

            user.ResetToken = resetToken;
            user.ResetTokenExpiry = tokenExpiry;

            await UpdateAsync(user);

            await SendPasswordResetEmail(email, resetToken);

            return (true, "If an account with this email exists, a reset link has been sent.");
        }

        public async Task<(bool Success, string Message)> ResetPasswordAsync(string token, string newPassword)
        {
            var user = await _db.Users.FirstOrDefaultAsync(u => u.ResetToken == token);
            if (user == null)
                return (false, "Invalid reset token.");

            if (user.ResetTokenExpiry < DateTime.UtcNow)
                return (false, "Reset token has expired.");

            if (!IsValidPassword(newPassword))
                return (false, "Password must be at least 8 characters long and include uppercase, lowercase, number, and special character.");

            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(newPassword, 12);
            user.ResetToken = null;
            user.ResetTokenExpiry = null;
            user.FailedLoginAttempts = 0;
            user.LockoutEndTime = null;

            await UpdateAsync(user);

            return (true, "Password reset successfully.");
        }

        // Helper methods

        private bool IsValidEmail(string email)
        {
            var emailRegex = @"^[^@\s]+@[^@\s]+\.[^@\s]+$";
            return Regex.IsMatch(email, emailRegex);
        }

        private bool IsValidPassword(string password)
        {
            if (password.Length < 8) return false;
            return Regex.IsMatch(password, @"[A-Z]") && Regex.IsMatch(password, @"[a-z]") &&
                   Regex.IsMatch(password, @"[0-9]") && Regex.IsMatch(password, @"[^A-Za-z0-9]");
        }

        private string GenerateToken()
        {
            return Guid.NewGuid().ToString("N");
        }

        private string GenerateJwtToken(User user)
        {
            var jwtSettings = _config.GetSection("Jwt");
            var secret = jwtSettings["Secret"] ?? throw new InvalidOperationException("Jwt:Secret configuration is required.");
            var issuer = jwtSettings["Issuer"] ?? throw new InvalidOperationException("Jwt:Issuer configuration is required.");
            var audience = jwtSettings["Audience"] ?? throw new InvalidOperationException("Jwt:Audience configuration is required.");

            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserID.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email ?? throw new InvalidOperationException("User email is required for JWT token generation.")),
                new Claim("name", user.Username ?? ""),
                new Claim("division", user.Division ?? ""),
                new Claim("businessUnit", user.BusinessUnit ?? ""),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secret));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: issuer,
                audience: audience,
                claims: claims,
                expires: DateTime.Now.AddHours(1),
                signingCredentials: creds
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }

        private (string SmtpServer, int Port, string Username, string Password, string FromEmail, string FromName) GetEmailSettings()
        {
            var emailSettings = _config.GetSection("Email");
            var smtpServer = emailSettings["SmtpServer"] ?? throw new InvalidOperationException("Email:SmtpServer configuration is required.");
            var portString = emailSettings["Port"] ?? throw new InvalidOperationException("Email:Port configuration is required.");
            var port = int.Parse(portString);
            var username = emailSettings["Username"] ?? throw new InvalidOperationException("Email:Username configuration is required.");
            var password = emailSettings["Password"] ?? throw new InvalidOperationException("Email:Password configuration is required.");
            var fromEmail = emailSettings["FromEmail"] ?? throw new InvalidOperationException("Email:FromEmail configuration is required.");
            var fromName = emailSettings["FromName"] ?? throw new InvalidOperationException("Email:FromName configuration is required.");
            return (smtpServer, port, username, password, fromEmail, fromName);
        }

        private async Task SendVerificationEmail(string email, string token)
        {
            var (smtpServer, port, username, password, fromEmail, fromName) = GetEmailSettings();

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(fromName, fromEmail));
            message.To.Add(new MailboxAddress("", email));
            message.Subject = "Verify Your Email - EclQrCodeManager";

            var bodyBuilder = new BodyBuilder();
            bodyBuilder.HtmlBody = $@"
                <h2>Welcome to EclQrCodeManager!</h2>
                <p>Please click the link below to verify your email address:</p>
                <a href='https://yourapp.com/verify-email?token={token}'>Verify Email</a>
                <p>This link will expire in 1 hour.</p>
            ";
            message.Body = bodyBuilder.ToMessageBody();

            using var client = new MailKit.Net.Smtp.SmtpClient();
            await client.ConnectAsync(smtpServer, port, MailKit.Security.SecureSocketOptions.StartTls);
            await client.AuthenticateAsync(username, password);
            await client.SendAsync(message);
            await client.DisconnectAsync(true);
        }

        private async Task SendPasswordResetEmail(string email, string token)
        {
            var (smtpServer, port, username, password, fromEmail, fromName) = GetEmailSettings();

            var message = new MimeMessage();
            message.From.Add(new MailboxAddress(fromName, fromEmail));
            message.To.Add(new MailboxAddress("", email));
            message.Subject = "Reset Your Password - EclQrCodeManager";

            var bodyBuilder = new BodyBuilder();
            bodyBuilder.HtmlBody = $@"
                <h2>Password Reset Request</h2>
                <p>Please click the link below to reset your password:</p>
                <a href='https://yourapp.com/reset-password?token={token}'>Reset Password</a>
                <p>This link will expire in 1 hour.</p>
            ";
            message.Body = bodyBuilder.ToMessageBody();

            using var client = new MailKit.Net.Smtp.SmtpClient();
            await client.ConnectAsync(smtpServer, port, MailKit.Security.SecureSocketOptions.StartTls);
            await client.AuthenticateAsync(username, password);
            await client.SendAsync(message);
            await client.DisconnectAsync(true);
        }
    }
}

using System.Collections.Generic;
using System.Threading.Tasks;
using EclQrCodeManagerAPI.Entities;

namespace EclQrCodeManagerAPI.Interfaces
{
    public interface IUserService
    {
        Task<IEnumerable<User>> GetAllAsync();
        Task<User?> GetByIdAsync(int id);
        Task<User> CreateAsync(User user);
        Task UpdateAsync(User user);
        Task DeleteAsync(int id);

        // New methods for secure registration and login
        Task<(bool Success, string Message)> RegisterAsync(string email, string password, string name, string division, string businessUnit);
        Task<(bool Success, string Message)> VerifyEmailAsync(string token);
        Task<(bool Success, string Message, string? Token, User? User)> LoginAsync(string email, string password);
        Task<(bool Success, string Message)> RequestPasswordResetAsync(string email);
        Task<(bool Success, string Message)> ResetPasswordAsync(string token, string newPassword);
    }
}

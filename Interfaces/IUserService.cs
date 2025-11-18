using System.Collections.Generic;
using System.Threading.Tasks;
using EclQrCodeManagerAPI.Entities;

namespace EclQrCodeManagerAPI.Interfaces
{
    public interface IUserService
    {
        Task<IEnumerable<User>> GetAllAsync();
        Task<User> GetByIdAsync(string id);
        Task<User> CreateAsync(User user);
        Task UpdateAsync(User user);
        Task DeleteAsync(string id);
    }
}
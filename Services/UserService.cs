using System.Collections.Generic;
using System.Threading.Tasks;
using EclQrCodeManagerAPI.Entities;
using EclQrCodeManagerAPI.Interfaces;
using EclQrCodeManagerAPI.Data;
using Microsoft.EntityFrameworkCore;

namespace EclQrCodeManagerAPI.Services
{
    public class UserService : IUserService
    {
        private readonly AppDbContext _db;
        public UserService(AppDbContext db) { _db = db; }

        public async Task<User> CreateAsync(User user)
        {
            await _db.Users.AddAsync(user);
            await _db.SaveChangesAsync();
            return user;
        }

        public async Task DeleteAsync(string id)
        {
            var user = await _db.Users.FindAsync(id);
            if (user == null) return;
            _db.Users.Remove(user);
            await _db.SaveChangesAsync();
        }

        public async Task<IEnumerable<User>> GetAllAsync() => await _db.Users.ToListAsync();

        public async Task<User> GetByIdAsync(string id) => await _db.Users.FindAsync(id);

        public async Task UpdateAsync(User user)
        {
            _db.Users.Update(user);
            await _db.SaveChangesAsync();
        }
    }
}
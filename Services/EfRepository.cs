using Microsoft.EntityFrameworkCore;
using EclQrCodeManagerAPI.Interfaces;
using EclQrCodeManagerAPI.Data;
using System.Collections.Generic;
using System.Threading.Tasks;

namespace EclQrCodeManagerAPI.Services
{
    public class EfRepository<T> : IRepository<T> where T : class
    {
        private readonly AppDbContext _db;
        private readonly DbSet<T> _set;
        public EfRepository(AppDbContext db) { _db = db; _set = _db.Set<T>(); }

        public async Task AddAsync(T entity) { await _set.AddAsync(entity); await _db.SaveChangesAsync(); }

        public async Task DeleteAsync(string id, string partitionKey = null)
        {
            // For simplicity, let callers fetch entity then Delete
            // (or implement find by id via EF keys)
        }

        public async Task<IEnumerable<T>> GetAllAsync() => await _set.ToListAsync();

        public async Task<T> GetByIdAsync(string id, string partitionKey = null) => await _set.FindAsync(id);

        public async Task UpdateAsync(T entity) { _set.Update(entity); await _db.SaveChangesAsync(); }
    }
}
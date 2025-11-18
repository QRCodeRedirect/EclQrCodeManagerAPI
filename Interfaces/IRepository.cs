using System;

using System.Collections.Generic;

using System.Threading.Tasks;

namespace EclQrCodeManagerAPI.Interfaces

{

    public interface IRepository<T> where T : class

    {

        Task<T> GetByIdAsync(string id, string partitionKey = null);

        Task<IEnumerable<T>> GetAllAsync();

        Task AddAsync(T entity);

        Task UpdateAsync(T entity);

        Task DeleteAsync(string id, string partitionKey = null);

    }

}


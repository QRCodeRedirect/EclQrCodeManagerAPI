using EclQrCodeManagerAPI.Entities;
using EclQrCodeManagerAPI.Interfaces;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace EclQrCodeManagerAPI.Controllers
{
    

    [ApiController]

    [Route("api/[controller]")]

    public class UsersController : ControllerBase

    {

        private readonly IUserService _service;

        public UsersController(IUserService service) { _service = service; }

        [HttpGet]

        public async Task<IActionResult> GetAll() => Ok(await _service.GetAllAsync());

        [HttpGet("{id}")]

        public async Task<IActionResult> Get(string id)

        {

            var u = await _service.GetByIdAsync(id);

            if (u == null) return NotFound();

            return Ok(u);

        }

        [HttpPost]

        public async Task<IActionResult> Create([FromBody] User user)

        {

            var created = await _service.CreateAsync(user);

            return CreatedAtAction(nameof(Get), new { id = created.Id }, created);

        }

        [HttpPut("{id}")]

        public async Task<IActionResult> Update(string id, [FromBody] User user)

        {

            if (id != user.Id) return BadRequest();

            await _service.UpdateAsync(user);

            return NoContent();

        }

        [HttpDelete("{id}")]

        public async Task<IActionResult> Delete(string id)

        {

            await _service.DeleteAsync(id);

            return NoContent();

        }

    }


}

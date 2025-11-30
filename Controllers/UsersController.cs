using EclQrCodeManagerAPI.Entities;
using EclQrCodeManagerAPI.Interfaces;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Cors;

namespace EclQrCodeManagerAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [EnableCors("AllowAll")]
    public class UsersController : ControllerBase
    {
        private readonly IUserService _service;

        public UsersController(IUserService service) { _service = service; }

        // Existing CRUD endpoints (consider protecting these with authorization)
        [HttpGet]
        [Authorize]
        public async Task<IActionResult> GetAll() => Ok(await _service.GetAllAsync());

        [HttpGet("{id}")]
        [Authorize]
        public async Task<IActionResult> Get(int id)
        {
            var u = await _service.GetByIdAsync(id);
            if (u == null) return NotFound();
            return Ok(u);
        }

        [HttpPost]
        [Authorize]
        public async Task<IActionResult> Create([FromBody] User user)
        {
            var created = await _service.CreateAsync(user);
            return CreatedAtAction(nameof(Get), new { id = created.UserID }, created);
        }

        [HttpPut("{id}")]
        [Authorize]
        public async Task<IActionResult> Update(int id, [FromBody] User user)
        {
            if (id != user.UserID) return BadRequest();
            await _service.UpdateAsync(user);
            return NoContent();
        }

        [HttpDelete("{id}")]
        [Authorize]
        public async Task<IActionResult> Delete(int id)
        {
            await _service.DeleteAsync(id);
            return NoContent();
        }

        // New secure registration and login endpoints

        [HttpPost("register")]
        [AllowAnonymous]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            var (success, message) = await _service.RegisterAsync(request.Email, request.Password, request.Name, request.Division, request.BusinessUnit);
            if (!success)
                return BadRequest(new { message });

            return Ok(new { message });
        }

        [HttpGet("verify-email")]
        [AllowAnonymous]
        public async Task<IActionResult> VerifyEmail([FromQuery] string token)
        {
            var (success, message) = await _service.VerifyEmailAsync(token);
            if (!success)
                return BadRequest(new { message });

            return Ok(new { message });
        }

        [HttpPost("login")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            var (success, message, token, user) = await _service.LoginAsync(request.Email, request.Password);
            if (!success || token == null || user == null)
                return BadRequest(new { message });

            // Set HttpOnly cookie
            Response.Cookies.Append("authToken", token, new Microsoft.AspNetCore.Http.CookieOptions
            {
                HttpOnly = true,
                Secure = true,
                SameSite = Microsoft.AspNetCore.Http.SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddHours(1)
            });

            return Ok(new
            {
                message,
                user = new
                {
                    user.UserID,
                    user.Email,
                    user.Username,
                    user.Division,
                    user.BusinessUnit,
                    user.LastLoginDate
                }
            });
        }

        [HttpPost("request-reset")]
        [AllowAnonymous]
        public async Task<IActionResult> RequestPasswordReset([FromBody] ResetRequest request)
        {
            var (success, message) = await _service.RequestPasswordResetAsync(request.Email);
            // Always return success message for security
            return Ok(new { message });
        }

        [HttpPost("reset-password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest request)
        {
            var (success, message) = await _service.ResetPasswordAsync(request.Token, request.NewPassword);
            if (!success)
                return BadRequest(new { message });

            return Ok(new { message });
        }
    }

    // Request models
    public class RegisterRequest
    {
        public required string Email { get; set; }
        public required string Password { get; set; }
        public required string Name { get; set; }
        public required string Division { get; set; }
        public required string BusinessUnit { get; set; }
    }

    public class LoginRequest
    {
        public required string Email { get; set; }
        public required string Password { get; set; }
    }

    public class ResetRequest
    {
        public required string Email { get; set; }
    }

    public class ResetPasswordRequest
    {
        public required string Token { get; set; }
        public required string NewPassword { get; set; }
    }
}

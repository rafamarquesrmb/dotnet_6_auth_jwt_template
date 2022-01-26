using AuthJwtDotnet.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace AuthJwtDotnet.Controllers;

[Authorize]
[ApiController]
public class AccountController : ControllerBase
{
    [AllowAnonymous]
    [HttpGet("/login")]
    public IActionResult Login([FromServices]TokenService _tokenService)
    {
        var token = _tokenService.GenerateToken(null);
        return Ok(token);
    }

    [Authorize(Roles = "user")]
    [HttpGet("/user")]
    public IActionResult GetUser() => Ok(User.Identity.Name);

    [Authorize(Roles = "author")]
    [HttpGet("/author")]
    public IActionResult GetAuthor() => Ok(User.Identity.Name);

    [Authorize(Roles = "admin")]
    [HttpGet("/admin")]
    public IActionResult GetAdmin() => Ok(User.Identity.Name);
}


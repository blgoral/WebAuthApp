using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using WebAuth.Data;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace WebAuth.Controllers;

public class TokenController : Controller
{
    private readonly ApplicationDbContext _context;
    private readonly UserManager<IdentityUser> _userManager;

    public TokenController(ApplicationDbContext context, UserManager<IdentityUser> userManager)
    {
        _context = context;
        _userManager = userManager;
    }

    [Route("/token")]
    [HttpPost]
    public async Task<IActionResult> Create(string username, string password)
    {
        if (await IsValidUserNameAndPassword(username, password))
        {
            var token = await GenerateToken(username);
            var response = new ObjectResult(token);
            var cookieOptions = new CookieOptions()
            {
                Path = "/",
                Expires = DateTimeOffset.UtcNow.AddHours(1),
                HttpOnly = true
            };
            Response.Cookies.Append("token", token, cookieOptions);
            return response;
        }
        else
        {
            return BadRequest();
        }
    }

    private async Task<bool> IsValidUserNameAndPassword(string? username, string? password)
    {
        if (username is null || password is null) return false;
        var user = await _userManager.FindByEmailAsync(username);
        return await _userManager.CheckPasswordAsync(user, password);

    }

    private async Task<dynamic> GenerateToken(string username)
    {
        var user = await _userManager.FindByEmailAsync(username);
        var roles = from ur in _context.UserRoles
            join r in _context.Roles on ur.RoleId equals r.Id
            where ur.UserId == user.Id
            select new {ur.UserId, ur.RoleId, r.Name};

        var claims = new List<Claim>
        {
            new Claim(ClaimTypes.Name, username),
            new Claim(ClaimTypes.NameIdentifier, user.Id),
            new Claim(JwtRegisteredClaimNames.Nbf, new DateTimeOffset(DateTime.Now).ToUnixTimeSeconds().ToString()),
            new Claim(JwtRegisteredClaimNames.Exp, new DateTimeOffset(DateTime.Now.AddDays(1)).ToUnixTimeSeconds().ToString())
        };

        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role.Name));
        }

        var token = new JwtSecurityToken(
            new JwtHeader(
                new SigningCredentials(
                    new SymmetricSecurityKey(Encoding.UTF8.GetBytes("MySecretKeyIsSecretSoDoNotTell")),
                    SecurityAlgorithms.HmacSha256)),
                    new JwtPayload(claims));

        var output = new JwtSecurityTokenHandler().WriteToken(token);

        return output;
    }
}

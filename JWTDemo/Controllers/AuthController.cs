using JWTDemo.Dtos;
using JWTDemo.Models;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using Encoding = System.Text.Encoding;

namespace JWTDemo.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        public static User user = new User();
        private readonly IConfiguration configuration;

        public AuthController(IConfiguration configuration)
        {
            this.configuration = configuration;
        }

        [HttpPost("register")]
        public async Task<ActionResult<User>> Register(UserDto userDtoRequest)
        {
            CreatePasswordHash(userDtoRequest.Password, out byte[] passwordHash, out byte[] passwordSalt);

            user.UserName = userDtoRequest.UserName;
            user.PasswordHash = passwordHash;
            user.PasswordSalt = passwordSalt;

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto userDtorequest)
        {
            if(user.UserName != userDtorequest.UserName)
            {
                return BadRequest("User not found");
            }

            if(!VerifyPasswordHash(userDtorequest.Password, user.PasswordHash, user.PasswordSalt))
            {
                return BadRequest("Invalid login");
            }

            string token = CreateToken();

            return Ok(token);
        }

        /// <summary>
        /// 1. Create claim based on username or other property except password
        /// 2. create security key by encoding the key from appsettings
        /// 3. create credentials by using key and same algo used to encode password hash & salt
        /// 4. create JWT token using claims, expiry, credentials
        /// 5. write token into string and return
        /// </summary>
        /// <returns></returns>
        private string CreateToken()
        {
            List<Claim> claims = new List<Claim>()
            {
                new Claim(ClaimTypes.Name, user.UserName)
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(configuration.GetSection("Appsettings:Token").Value));

            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                    claims: claims,
                    expires: DateTime.UtcNow.AddDays(1),
                    signingCredentials: credentials
                );

            var jwtToken = new JwtSecurityTokenHandler().WriteToken(token);

            return jwtToken;
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using(var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }
    }
}

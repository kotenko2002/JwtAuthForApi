using System.Security.Cryptography;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;
using JwsAuthForApi.Data;
using JwsAuthForApi.Dto;
using System.Linq;
using System.Collections.Generic;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using Microsoft.Extensions.Configuration;
using System.IdentityModel.Tokens.Jwt;
using System;
using JwsAuthForApi.Repositories;
using Newtonsoft.Json;

namespace JwsAuthForApi.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _configuration;
        private readonly AuthApiContext _authApiContext;

        public AuthController(IConfiguration configuration, AuthApiContext authApiContext)
        {
            _configuration = configuration;
            _authApiContext = authApiContext;
        }

        [HttpPost("register")]
        public async Task<ActionResult<User1>> Registor(UserDto model)
        {
            if (!ModelState.IsValid)
            {
                return BadRequest("To short username.");
            }

            if(_authApiContext.Users.FirstOrDefault(item => item.Username == model.Username) != null)
            {
                return BadRequest("User with such username is already exist.");
            }

            CreatePasswordHash(model.Password, out byte[] passwordHash, out byte[] passwordSalt);

            User user = new User()
            {
                Username = model.Username,
                PasswordHash = JsonConvert.SerializeObject(passwordHash),
                PasswordSalt = JsonConvert.SerializeObject(passwordSalt)
            };

            _authApiContext.Users.Add(user);
            _authApiContext.SaveChanges();

            return Ok(user);
        }

        [HttpPost("login")]
        public async Task<ActionResult<string>> Login(UserDto model)
        {
            var user = _authApiContext.Users.FirstOrDefault(item => item.Username == model.Username);
            if (user == null)
            {
                return BadRequest("User not found.");
            }

            if (!VerifyPasswordHash(model.Password,
                    JsonConvert.DeserializeObject<byte[]>(user.PasswordHash),
                    JsonConvert.DeserializeObject<byte[]>(user.PasswordSalt)))
            {
                return BadRequest("Wrong password.");
            }

            string token = CreateToken(user);
            return Ok(token);
        }

        private void CreatePasswordHash(string password, out byte[] passwordHash, out byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512())
            {
                passwordSalt = hmac.Key;
                passwordHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
            }
        }

        private bool VerifyPasswordHash(string password, byte[] passwordHash, byte[] passwordSalt)
        {
            using (var hmac = new HMACSHA512(passwordSalt))
            {
                var computedHash = hmac.ComputeHash(System.Text.Encoding.UTF8.GetBytes(password));
                return computedHash.SequenceEqual(passwordHash);
            }
        }

        private string CreateToken(User user)
        {
            List<Claim> claims = new List<Claim>
            {
                new Claim(ClaimTypes.Name, user.Username)
            };

            var key = new SymmetricSecurityKey(System.Text.Encoding.UTF8.GetBytes(
                _configuration.GetSection("AppSettings:Token").Value));

            var cred = new SigningCredentials(key, SecurityAlgorithms.HmacSha512Signature);

            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(1),
                signingCredentials: cred
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);

            return jwt;
        }
    }
}

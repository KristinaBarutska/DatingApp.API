using DatingApp.API.Data;
using DatingApp.API.Dtos;
using DatingApp.API.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using System;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace DatingApp.API.Controllers
{
    [Route("api/[controller]")]

    public class AuthController: Controller
    {
        private readonly IAuthRepository _repo;
        private readonly IConfiguration _config;

        public AuthController(IAuthRepository repo, IConfiguration config)
        {
            _repo = repo;
            _config = config;
        }

        [HttpPost("register")]
        
        public async Task<IActionResult>Register([FromBody]UserForRegisterDto userForRegisterDto)
        {
            if(await _repo.UserExists(userForRegisterDto.Username))
            {
                 ModelState.AddModelError("Usename","Username alredy exists!");
            }
            if(!ModelState.IsValid)
            {
                return BadRequest(ModelState);
            }
            userForRegisterDto.Username= userForRegisterDto.Username.ToLower();

            

            var userToCreate= new User{Username=userForRegisterDto.Username};
            var createUser= await _repo.Register(userToCreate, userForRegisterDto.Password);

            return StatusCode(201);
        }
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody]UserForLoginDto userForLoginDto)
        {
            var userFromRepo= await _repo.Login(userForLoginDto.Username.ToLower(), userForLoginDto.Password);
            if (userFromRepo==null)
                return Unauthorized();
            //return Ok(userFromRepo.Username);

            //generate token   
            var tokenHandler = new JwtSecurityTokenHandler();
            var keyByteArray =Encoding.ASCII.GetBytes(_config.GetSection("AppSettings:Token").Value);
            var signingKey= new SymmetricSecurityKey(keyByteArray);
            var tokenDescriptor= new SecurityTokenDescriptor
            {
                Subject = new ClaimsIdentity(new Claim[]{
                    new Claim(ClaimTypes.NameIdentifier, userFromRepo.Id.ToString()),
                    new Claim(ClaimTypes.Name, userFromRepo.Username)
                }),
                Expires = DateTime.Now.AddDays(1),
                SigningCredentials = new SigningCredentials(signingKey, 
                    SecurityAlgorithms.HmacSha512Signature)
            };
            //return Ok(tokenDescriptor.Subject.Name.ToString());
            try
            {
            var token = tokenHandler.CreateToken(tokenDescriptor);  
            var tokenString= tokenHandler.WriteToken(token);

            return Ok(new {tokenString});
            }
            catch(SystemException exception){
                return Ok(exception.ToString());
            }
            
            
        }
        
    }
}
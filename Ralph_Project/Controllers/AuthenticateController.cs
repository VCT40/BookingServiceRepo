using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using Ralph_Project.Models; // Custom model namespace
using Ralph_Project.Modles; 
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace Ralph_Project.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticateController : ControllerBase
    {
        // Dependencies for managing users, roles, and configuration
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly IConfiguration _configuration;

        // Constructor to inject dependencies
        public AuthenticateController(
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            IConfiguration configuration)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _configuration = configuration;
        }

        // Method to generate a JWT token based on a list of claims
        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            // Get the secret key from configuration and encode it
            var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]));

            // Create a new JWT token with the specified claims, issuer, audience, and expiration time
            var token = new JwtSecurityToken(
                issuer: _configuration["JWT:ValidIssuer"],  // Valid issuer
                audience: _configuration["JWT:ValidIssuer"],  // Valid audience
                expires: DateTime.Now.AddHours(1),  // Token expiration time (1 hour)
                claims: authClaims,  // Claims to include in the token
                signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha256)  // Signing credentials using HMAC SHA256
                );

            return token;
        }

        // Endpoint to handle user login
        [HttpPost]
        [Route("login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            // Find the user by username
            var user = await _userManager.FindByNameAsync(model.Username);

            // Check if user exists and the provided password is correct
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                // Get the roles associated with the user
                var userRoles = await _userManager.GetRolesAsync(user);

                // Prepare claims for the JWT token
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),  // Claim for the username
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),  // Unique identifier for the token
                };

                // Add role claims for each user role
                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                // Generate the token
                var token = GetToken(authClaims);

                // Return the token and its expiration time
                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });
            }
            return Unauthorized();  // Return Unauthorized if login fails
        }

        // Endpoint to handle user registration
        [HttpPost]
        [Route("register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            // Check if the user already exists
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "User already exists!" });

            // Create a new user with the provided details
            IdentityUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),  // Unique identifier for the user
                UserName = model.Username
            };

            // Attempt to create the user with the specified password
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

            // Ensure the 'User' role exists, and create it if it doesn't
            if (!await _roleManager.RoleExistsAsync(UserRoles.User))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.User));

            // Add the newly created user to the 'User' role
            if (await _roleManager.RoleExistsAsync(UserRoles.User))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.User);
            }

            // Return success message
            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }

        // Endpoint to register a new admin user (restricted to existing admins)
        [Authorize(Roles = UserRoles.Admin)]
        [HttpPost]
        [Route("register-admin")]
        public async Task<IActionResult> RegisterAdmin([FromBody] RegisterModel model)
        {
            // Check if the user already exists
            var userExists = await _userManager.FindByNameAsync(model.Username);
            if (userExists != null)
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "User already exists!" });

            // Create a new user with the provided details
            IdentityUser user = new()
            {
                Email = model.Email,
                SecurityStamp = Guid.NewGuid().ToString(),  // Unique identifier for the user
                UserName = model.Username
            };

            // Attempt to create the user with the specified password
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
                return StatusCode(StatusCodes.Status500InternalServerError,
                    new Response { Status = "Error", Message = "User creation failed! Please check user details and try again." });

            // Ensure the 'Admin' role exists, and create it if it doesn't
            if (!await _roleManager.RoleExistsAsync(UserRoles.Admin))
                await _roleManager.CreateAsync(new IdentityRole(UserRoles.Admin));

            // Add the newly created user to the 'Admin' role
            if (await _roleManager.RoleExistsAsync(UserRoles.Admin))
            {
                await _userManager.AddToRoleAsync(user, UserRoles.Admin);
            }

            // Return success message
            return Ok(new Response { Status = "Success", Message = "User created successfully!" });
        }

    }
}

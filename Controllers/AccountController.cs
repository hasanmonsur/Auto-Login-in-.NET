using AutoLoginWebApp.Models;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using AutoLoginWebApp.Services;

namespace AutoLoginWebApp.Controllers
{
    public class AccountController : Controller
    {
        private readonly ILogger<AccountController> _logger;
        private readonly TokenService _tokenService;

        public AccountController(ILogger<AccountController> logger, TokenService tokenService)
        {
            _logger = logger;
            _tokenService = tokenService;
        }

        public IActionResult Login()
        {
            return View();
        }


        [HttpPost]
        public async Task<IActionResult> Login(string jwt)
        {
            if (string.IsNullOrEmpty(jwt))
            {
                return BadRequest("Invalid token");
            }

            // 1. Validate the JWT token
            var principal =  await _tokenService.ValidateToken(jwt);

            if (principal == null)
            {
                return Unauthorized();
            }

            // 2. Create auth properties
            var authProperties  = new AuthenticationProperties
            {
                IsPersistent = true,
                ExpiresUtc = DateTimeOffset.UtcNow.AddMinutes(60) // Match token expiration
            };

            // 3. Sign in the user
            // 3. Sign in the user
            await HttpContext.SignInAsync(
                CookieAuthenticationDefaults.AuthenticationScheme,
                principal, // Pass the ClaimsPrincipal here
                authProperties); // Pass AuthenticationProperties as third parameter

            // 4. Set the JWT as an HTTP-only cookie (optional)
            Response.Cookies.Append("accessToken", jwt, new CookieOptions
            {
                HttpOnly = true,
                Secure = true, // Enable in production (requires HTTPS)
                SameSite = SameSiteMode.Strict,
                Expires = DateTime.UtcNow.AddMinutes(60) // Match token expiration
            });



            return RedirectToAction("Index", "Home");
        }


        [HttpPost]
        public async Task<IActionResult> LoginForm(LoginModel model)
        {
            var httpClient = new HttpClient();
            var response = await httpClient.PostAsJsonAsync(
                "http://localhost:5160/api/auth/login",
                new { model.Email, model.Password });

            if (response.IsSuccessStatusCode)
            {
                var authResponse = await response.Content.ReadFromJsonAsync<AuthResponse>();

                Response.Cookies.Append("accessToken", authResponse.Token); 
                Response.Cookies.Append("refreshToken", authResponse.RefreshToken);

                // Cookies will be set by the API response
                return RedirectToAction("Index", "Home");
            }

            ModelState.AddModelError("", "Invalid login attempt");
            return View();
        }

        [Authorize]
        public async Task<IActionResult> Logout()
        {
            var httpClient = new HttpClient();
            await httpClient.PostAsync(
                "http://localhost:5160/api/auth/logout",
                null);

            // Clear local cookies
            Response.Cookies.Delete("accessToken");
            Response.Cookies.Delete("refreshToken");

            return RedirectToAction("Login");
        }
    }
}

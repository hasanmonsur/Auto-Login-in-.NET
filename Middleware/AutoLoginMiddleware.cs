using AutoLoginWebApp.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authentication;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AutoLoginWebApp.Services;

namespace AutoLoginWebApp.Middleware
{
    public class AutoLoginMiddleware
    {
        private readonly RequestDelegate _next;
        
        public AutoLoginMiddleware(RequestDelegate next)
        {
            _next = next;
           
        }

        
        public async Task InvokeAsync(HttpContext context)
        {
            if (!context.User.Identity?.IsAuthenticated ?? false)
            {
                var token = context.Request.Cookies["accessToken"];
                if (!string.IsNullOrEmpty(token))
                {
                    var result = await context.AuthenticateAsync(JwtBearerDefaults.AuthenticationScheme);
                    if (result.Succeeded)
                    {
                        context.User = result.Principal;
                        Console.WriteLine("User set from token");
                    }
                    else
                    {
                        Console.WriteLine("Authentication failed in middleware");
                    }
                }
            }
            await _next(context);
        }

        /*
        public async Task Invoke(HttpContext context)
        {
            // Skip if already authenticated or accessing auth endpoints
            if (!context.User.Identity.IsAuthenticated &&
                !context.Request.Path.StartsWithSegments("/Account"))
            {
                var refreshToken = context.Request.Cookies["refreshToken"];
                if (!string.IsNullOrEmpty(refreshToken))
                {
                    // Call your API to validate refresh token
                    var httpClient = new HttpClient();
                    httpClient.BaseAddress = new Uri("http://localhost:5160");

                    // Forward the refresh token cookie
                    var request = new HttpRequestMessage(
                        HttpMethod.Post, "api/auth/refresh");
                    request.Headers.Add("Cookie", $"refreshToken={refreshToken}");

                    var response = await httpClient.SendAsync(request);

                    if (response.IsSuccessStatusCode)
                    {
                        var result = await response.Content.ReadFromJsonAsync<RefreshTokenResult>();

                        // Set new cookies
                        context.Response.Cookies.Append("accessToken", result.AccessToken, new CookieOptions
                        {
                            HttpOnly = true,
                            Secure = true,
                            SameSite = SameSiteMode.Strict
                        });

                        // Redirect to refresh the auth state
                        context.Response.Redirect(context.Request.Path);
                        return;
                    }
                }
            }

            await _next(context);
        }

        */
    }


    public static class AutoLoginMiddlewareExtensions
    {
        public static IApplicationBuilder UseAutoLoginMiddleware(this IApplicationBuilder builder)
        {
            return builder.UseMiddleware<AutoLoginMiddleware>();
        }
    }
}

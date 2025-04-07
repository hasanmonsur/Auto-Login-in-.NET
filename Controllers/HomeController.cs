using System.Diagnostics;
using Microsoft.AspNetCore.Mvc;
using AutoLoginWebApp.Models;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using AutoLoginWebApp.Services;

namespace AutoLoginWebApp.Controllers;

public class HomeController : Controller
{
    private readonly ILogger<HomeController> _logger;
    private readonly TokenService _tokenService;
    public HomeController(ILogger<HomeController> logger, TokenService tokenService)
    {
        _logger = logger;
        _tokenService = tokenService;
    }

    [Authorize]
    public async Task<IActionResult> IndexAsync()
    {
        var authToken = Request.Cookies["accessToken"];

        if (string.IsNullOrEmpty(authToken))
        {
            return RedirectToAction("Login");
        }


        // Verify token and get user claims
        var principal = await _tokenService.ValidateToken(authToken);


        var userId = principal.FindFirst(ClaimTypes.NameIdentifier)?.Value;
        var email = principal.FindFirst(ClaimTypes.Email)?.Value;

        Console.WriteLine($"User ID: {userId}, Username: {email}");
        if (string.IsNullOrEmpty(userId))
        {
            return Unauthorized("No authenticated user found");
        }
        return View(model: $"Welcome to Business App, {email} (ID: {userId})!");
    }

    // Temporary for testing
    //public IActionResult SetToken()
    //{
    //    var token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1laWRlbnRpZmllciI6IjEiLCJodHRwOi8vc2NoZW1hcy54bWxzb2FwLm9yZy93cy8yMDA1LzA1L2lkZW50aXR5L2NsYWltcy9uYW1lIjoidGVzdCIsImV4cCI6MTcxMjM0NTY3OH0.8y8z8y8z8y8z8y8z8y8z8y8z8y8z8y8z8y8z8y8z8y8"; // Replace with valid token from AuthApi
    //    Response.Cookies.Append("accessToken", token, new CookieOptions
    //    {
    //        Path = "/",
    //        SameSite = SameSiteMode.Lax,
    //        Expires = DateTimeOffset.UtcNow.AddMinutes(15)
    //    });
    //    return RedirectToAction("Index");
    //}

    public IActionResult Privacy()
    {
        return View();
    }

    [ResponseCache(Duration = 0, Location = ResponseCacheLocation.None, NoStore = true)]
    public IActionResult Error()
    {
        return View(new ErrorViewModel { RequestId = Activity.Current?.Id ?? HttpContext.TraceIdentifier });
    }
}

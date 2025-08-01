using System.Security.Claims;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using SSO_TEST_BACK.Helpers;

namespace SSO_TEST_BACK.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly SignInManager<IdentityUser> _signInManager;
    private readonly UserManager<IdentityUser> _userManager;
    private readonly JwtTokenGenerator _tokenGenerator;
    private readonly IConfiguration _configuration;

    public AuthController(
        SignInManager<IdentityUser> signInManager,
        UserManager<IdentityUser> userManager,
        JwtTokenGenerator tokenGenerator,
        IConfiguration configuration)
    {
        _signInManager = signInManager;
        _userManager = userManager;
        _tokenGenerator = tokenGenerator;
        _configuration = configuration;
    }

    [HttpGet("external-login/{provider}")]
    public IActionResult ExternalLogin(string provider, string? returnUrl = null)
    {
        var redirectUrl = Url.Action(nameof(ExternalLoginCallback), "Auth", new { ReturnUrl = returnUrl });
        var properties = _signInManager.ConfigureExternalAuthenticationProperties(provider, redirectUrl);
        return Challenge(properties, provider);
    }

    [HttpGet("external-login-callback")]
    public async Task<IActionResult> ExternalLoginCallback(string? remoteError = null, string? returnUrl = null)
    {
        if (remoteError != null)
        {
            return BadRequest($"Error from external provider: {remoteError}");
        }

        var info = await _signInManager.GetExternalLoginInfoAsync();
        if (info == null)
        {
            return BadRequest("Error loading external login information.");
        }

        var signInResult = await _signInManager.ExternalLoginSignInAsync(info.LoginProvider, info.ProviderKey, false);
        IdentityUser? user;

        if (signInResult.Succeeded)
        {
            user = await _userManager.FindByLoginAsync(info.LoginProvider, info.ProviderKey);
        }
        else
        {
            var email = info.Principal.FindFirstValue(ClaimTypes.Email);
            if (email == null)
            {
                return BadRequest("Email claim not received.");
            }

            user = await _userManager.FindByEmailAsync(email);
            if (user == null)
            {
                user = new IdentityUser { UserName = email, Email = email };
                await _userManager.CreateAsync(user);
            }

            await _userManager.AddLoginAsync(user, info);
        }

        if (user == null)
        {
            return BadRequest("User not found.");
        }

        var token = _tokenGenerator.GenerateToken(user.Id, user.Email!, info.LoginProvider);
        var frontendUrl = _configuration["FrontendUrl"];
        return Redirect($"{frontendUrl}?token={token}");
    }
}

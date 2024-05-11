using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using User.Management.API.Models;
using System.IdentityModel.Tokens.Jwt;
using User.Management.Service.Services;
using User.Management.Service.Models;
using System.Security.Claims;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Authorization;
using static System.Net.WebRequestMethods;
using User.Management.Service.Models.Authentication.SignUp;
using User.Management.Service.Models.Authentication.Login;
using NuGet.Common;
using User.Management.Data.Models;
using User.Management.Service.Models.Authentication.User;
using User.Management.API.Models.Authentication.Login;

namespace User.Management.API.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly IEmailService _emailService;
        private readonly IUserManagement _user;
        public AuthenticationController(UserManager<ApplicationUser> userManager,
            IEmailService emailService, IUserManagement user, IConfiguration configuration)
        {
            _userManager = userManager;
            _emailService = emailService;
            _user = user;
        }
        [HttpGet("test")]
        public string get()
        {
            return "working";
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterUser registerUser)
        {
            //Check User Exist 
            var tokenResponse = await _user.CreateTokenWithUserAsync(registerUser);
            if (tokenResponse.IsSuccess && tokenResponse.Response != null)
            {
                await _user.AssignRoleToUserAsync(registerUser.Roles, tokenResponse.Response.User);
                var confirmationLink = Url.Action(nameof(ConfirmEmail), "Authentication", new { tokenResponse.Response.Token, email = registerUser.Email }, Request.Scheme);
                var message = new Message(new string[] { registerUser.Email! }, "Confirmation email link", confirmationLink!);
                var responseMsg = _emailService.SendEmail(message);

                return StatusCode(StatusCodes.Status200OK,
                          new Response { IsSuccess = true, Message = $"{tokenResponse.Message}{responseMsg}" });
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                          new Response { Message = tokenResponse.Message, IsSuccess = false });
        }
        [HttpGet("TestEmail")]
        public IActionResult TestEmail()
        {
            var message = new Message(new string[] { "bachusrivarsha@gmail.com" }, "Test", "Testing....");
            _emailService.SendEmail(message);
            return StatusCode(StatusCodes.Status200OK,
                    new Response { Status = "Success", Message = $"User created & Email  SuccessFully" });

        }
        [HttpGet("ConfirmEmail")]
        public async Task<IActionResult> ConfirmEmail(string token, string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var result = await _userManager.ConfirmEmailAsync(user, token);
                if (result.Succeeded)
                {
                    return StatusCode(StatusCodes.Status200OK,
                      new Response { Status = "Success", Message = "Email Verified Successfully" });
                }
            }
            return StatusCode(StatusCodes.Status500InternalServerError,
                       new Response { Status = "Error", Message = "This User Doesnot exist!" });
        }
        [HttpPost("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel loginModel)
        {
            var loginOtpResponse = await _user.GetOtpByLoginAsync(loginModel);

            if (loginOtpResponse.Response != null)
            {
                var user = loginOtpResponse.Response.User;
                if (user.TwoFactorEnabled)
                {
                    var token = loginOtpResponse.Response.Token;
                    var message = new Message(new string[] { user.Email! }, "OTP Confirmation", token);
                    _emailService.SendEmail(message);
                    return StatusCode(StatusCodes.Status200OK,
                      new Response { IsSuccess = loginOtpResponse.IsSuccess, Status = "Success", Message = $"OTP sent successfully to {user.Email}" });
                }
                if (user != null && await _userManager.CheckPasswordAsync(user, loginModel.Password))
                {
                    var serviceResponse = await _user.GetJwtTokenAsync(user);
                    return Ok(serviceResponse);

                }
            }

            return Unauthorized();


        }
        [HttpPost("Login-2FA")]
        public async Task<IActionResult> LoginwithOTP(string code, string username)
        {
            var jwt = await _user.LoginUserWithJWTokenAsync(code, username);
            if (jwt.IsSuccess)
            {
                return Ok(jwt);
            }
            return StatusCode(StatusCodes.Status404NotFound,
                new Response { Status = "Success", Message = $"Invalid Code" });
        }

        [HttpPost("ForgotPassword")]
        [AllowAnonymous]
        public async Task<IActionResult> ForgotPassword([Required] string email)
        {
            var user = await _userManager.FindByEmailAsync(email);
            if (user != null)
            {
                var token = await _userManager.GeneratePasswordResetTokenAsync(user);
                var requestScheme = "http";
                var requestHost = "localhost:54493";
                var forgotPasswordlink = $"{requestScheme}://{requestHost}/reset-password?token={token}&email={user.Email}"; ;
                var message = new Message(new string[] { user.Email! }, "Reset Your Password", $"Click <a href=\"{forgotPasswordlink}\">here</a> to reset your password.");
                _emailService.SendEmail(message);
                return StatusCode(StatusCodes.Status200OK,
                  new Response { Status = "Success", Message = $"Reset Password link sent sucessfully to {user.Email}" });
            }
            return StatusCode(StatusCodes.Status400BadRequest,
                       new Response { Status = "Error", Message = "This User Doesnot exist! Please check the password" });
        }

        [HttpGet("Reset-Password")]
        public async Task<IActionResult> ResetPassword(string token, string email)
        {
            var model = new ResetPassword { Token = token, Email = email };
            return Ok(new { model });
        }
        [HttpPost("Reset-Password")]
        [AllowAnonymous]
        public async Task<IActionResult> ResetPassword(ResetPassword resetPassword)
        {
            var user = await _userManager.FindByEmailAsync(resetPassword.Email);
            if (user != null)
            {
                var resetPasswordResult = await _userManager.ResetPasswordAsync(user, resetPassword.Token, resetPassword.Password);
                if (!resetPasswordResult.Succeeded)
                {
                    foreach (var error in resetPasswordResult.Errors)
                    {
                        ModelState.AddModelError(error.Code, error.Description);
                    }
                    return Ok(ModelState);
                }
                return StatusCode(StatusCodes.Status200OK,
                  new Response { Status = "Success", Message = $"Password has been changed" });
            }
            return StatusCode(StatusCodes.Status400BadRequest,
                       new Response { Status = "Error", Message = "This User Doesnot exist! Please check the password" });
        }



        [HttpPost]
        [Route("Refresh-Token")]
        public async Task<IActionResult> RefreshToken(LoginResponse tokens)
        {
            var jwt = await _user.RenewAccessTokenAsync(tokens);
            if (jwt.IsSuccess)
            {
                return Ok(jwt);
            }
            return StatusCode(StatusCodes.Status404NotFound,
                new Response { Status = "Success", Message = $"Invalid Code" });
        }
    }
}
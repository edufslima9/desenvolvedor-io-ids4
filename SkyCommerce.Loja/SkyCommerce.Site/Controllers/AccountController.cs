using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using SkyCommerce.Site.Models;
using System;
using System.Threading.Tasks;

namespace SkyCommerce.Site.Controllers
{
    [Route("conta")]
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ILogger<AccountController> _logger;

        public AccountController(
            UserManager<IdentityUser> userManager,
            SignInManager<IdentityUser> signInManager,
            ILogger<AccountController> logger)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _logger = logger;
        }


        [HttpGet]
        [AllowAnonymous]
        [Route("entrar")]
        public async Task<IActionResult> Login(string returnUrl = null)
        {
            // Clear the existing external cookie to ensure a clean login process
            await HttpContext.SignOutAsync(IdentityConstants.ExternalScheme);

            ViewData["ReturnUrl"] = returnUrl;
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        [Route("entrar")]
        public async Task<IActionResult> Login(LoginViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (!ModelState.IsValid) return View(model);

            IdentityUser userIdentity;
            if (model.IsUsernameEmail())
            {
                userIdentity = await _userManager.FindByEmailAsync(model.Username);
            }
            else
            {
                userIdentity = await _userManager.FindByNameAsync(model.Username);
            }

            if (userIdentity != null)
            {
                var result = await _signInManager.PasswordSignInAsync(userIdentity.UserName, model.Password, model.RememberMe, true);

                if (result.Succeeded)
                {
                    _logger.LogInformation("Logado com sucesso");
                    return string.IsNullOrEmpty(returnUrl) ? RedirectToAction("Index", "Home") : RedirectToLocal(returnUrl);
                }
            }
            _logger.LogInformation("Erro no login");
            ModelState.AddModelError("", "Usuário ou senha inválido");
            return View(model);
        }

        [Authorize, Route("minha-conta")]
        public IActionResult MinhaConta()
        {
            return View();
        }

        private IActionResult RedirectToLocal(string returnUrl)
        {
            if (Url.IsLocalUrl(returnUrl))
            {
                return Redirect(returnUrl);
            }
            else
            {
                return RedirectToAction(nameof(HomeController.Index), "Home");
            }
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        [Route("cadastro")]
        public async Task<IActionResult> Registrar(RegistrarUsuarioViewModel model, string returnUrl = null)
        {
            ViewData["ReturnUrl"] = returnUrl;
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = new IdentityUser() { UserName = model.Email, Email = model.Email };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (result.Succeeded)
            {
                await _signInManager.PasswordSignInAsync(user, model.Password, true, true);
                return RedirectToAction("Index", "Home");
            }

            return View(model);
        }

        [Route("sair")]
        public async Task<IActionResult> Sair()
        {
            // Clear the existing external cookie to ensure a clean login process
            await _signInManager.SignOutAsync();

            return RedirectToAction("Index", "Home");
        }

        [Route("esqueci-senha")]
        public IActionResult EsqueciSenha()
        {
            return View();
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        [Route("esqueci-senha")]
        public async Task<IActionResult> EsqueciSenha(EsqueciSenhaViewModel model)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(model.Email);
                if (user == null)
                {
                    // Don't reveal that the user does not exist or is not confirmed
                    return RedirectToAction(nameof(EsqueciSenhaSucesso));
                }

                // For more information on how to enable account confirmation and password reset please
                // visit https://go.microsoft.com/fwlink/?LinkID=532713
                var code = await _userManager.GeneratePasswordResetTokenAsync(user);
                var callbackUrl = Url.Action(
                    action: nameof(AccountController.ResetSenha),
                    controller: "Account",
                    values: new { user.Id, code },
                    protocol: Request.Scheme);

                // For god sake! Only for demo pourposes!
                TempData["UrlReset"] = callbackUrl;

                return RedirectToAction(nameof(EsqueciSenhaSucesso));
            }

            // If we got this far, something failed, redisplay form
            return View(model);
        }

        [HttpGet]
        [AllowAnonymous]
        [Route("esqueci-minha-senha-sucesso")]
        public IActionResult EsqueciSenhaSucesso(string link)
        {
            return View(link);
        }

        [HttpGet]
        [AllowAnonymous]
        [Route("trocar-minha-senha")]
        public IActionResult ResetSenha(string code = null)
        {
            if (code == null)
            {
                throw new ApplicationException("A code must be supplied for password reset.");
            }

            var model = new ResetPasswordViewModel { Code = code };
            return View(model);
        }

        [HttpPost]
        [AllowAnonymous]
        [ValidateAntiForgeryToken]
        [Route("trocar-minha-senha")]
        public async Task<IActionResult> ResetSenha(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }
            var user = await _userManager.FindByEmailAsync(model.Email);
            if (user == null)
            {
                // Don't reveal that the user does not exist
                return RedirectToAction(nameof(ResetSenhaSucesso));
            }
            var result = await _userManager.ResetPasswordAsync(user, model.Code, model.Password);
            if (result.Succeeded)
            {
                return RedirectToAction(nameof(ResetSenhaSucesso));
            }
            return View();
        }
        [HttpGet]
        [AllowAnonymous]
        [Route("trocar-minha-senha-sucesso")]
        public IActionResult ResetSenhaSucesso()
        {
            return View();
        }


    }
}

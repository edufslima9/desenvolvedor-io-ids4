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
        [HttpGet]
        [Authorize]
        [Route("entrar")]
        public IActionResult Login(string returnUrl = null)
        {
            if (!String.IsNullOrWhiteSpace(returnUrl))
                return RedirectToAction(returnUrl);
            return RedirectToAction("Index", "Home");
        }

        [Authorize, Route("minha-conta")]
        public IActionResult MinhaConta()
        {
            return View();
        }

        [Route("sair")]
        public IActionResult Sair()
        {
            return SignOut("Cookies", "oidc");
        }
    }
}

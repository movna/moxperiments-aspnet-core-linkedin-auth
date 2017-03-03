using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace LinkedInAuth.Controllers
{
	public class HomeController : Controller
	{
		[Authorize]
		[HttpGet("")]
		public IActionResult Index()
		{
			// Accessing the values we set in OnCreatingTicketLinkedInAsync
			var id = User.FindFirst(ClaimTypes.NameIdentifier).Value;
			var email = User.FindFirst(ClaimTypes.Email).Value;
			var name = User.FindFirst(ClaimTypes.Name).Value;
			return View(new {id, email, name});
		}

		[HttpGet("signout")]
		public async Task<IActionResult> SignOut()
		{
			await HttpContext.Authentication.SignOutAsync(CookieAuthenticationDefaults.AuthenticationScheme).ConfigureAwait(false);
			return Json("signed out!");
		}
	}
}
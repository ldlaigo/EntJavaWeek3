using Microsoft.AspNetCore.Mvc;
using MyWebApplication.Models.EntityManager;
using MyWebApplication.Models.ViewModel;

namespace MyWebApplication.Controllers
{
    public class AccountController : Controller
    {
        public ActionResult SignUp()
        {
            return View();
        }
        public ActionResult Users()
        {
            UserManager um = new UserManager();
            UserModels user = um.GetAllUsers();
            return View(user);
        }
        [HttpPost]
        public ActionResult SignUp(UserModel user)
        {
            ModelState.Remove("AcountImage");
            if (ModelState.IsValid)
            {
                UserManager um = new UserManager();
                if (!um.IsLoginNameExist(user.LoginName))
                {
                    um.AddUserAccount(user);
                    // FormsAuthentication.SetAuthCookie(user.FirstName, false);
                    return RedirectToAction("", "Home");
                }
                else
                    ModelState.AddModelError("", "Login Name already taken.");
            }
            return View();
        }

        [HttpPut]
        public async Task<ActionResult> Update([FromBody] UserModel userData)
        {
            UserManager um = new UserManager();
            if (um.IsLoginNameExist(userData.LoginName))
            {
                um.UpdateUserAccount(userData);
                return RedirectToAction("Index");
            }
            return RedirectToAction("LoginNameNotFound");
        }

        [HttpGet]
        public ActionResult GetUsers()
        {
            var users = new UserManager().GetAllUsers();

            return View();
        }
    }
}

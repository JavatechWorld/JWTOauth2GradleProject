package GradleOauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ModelAttribute;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
@RequestMapping("/login")
public class LoginController {

	@Autowired
	JwtGeneratorValidator jwtgenval;

	ValidationHelper validationHelper = new ValidationHelper();

	@ModelAttribute("user")
	public UserLoginDTO userLoginDTO() {
		return new UserLoginDTO();
	}

	@GetMapping
	public String login(Authentication request) {
		if (validationHelper.validateReturn(request)) {
			return "redirect:/dashboard";
		} else {
			return "login";
		}
	}

	@GetMapping("/logout")
	public String logout(Authentication request) {
		validationHelper.clearData(request);
		return "login";
	}

}
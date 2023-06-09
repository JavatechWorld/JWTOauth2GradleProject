package GradleOauth2;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller

@RequestMapping("/dashboard")
public class DashboardController {

	@Autowired
	JwtGeneratorValidator jwtgenval;
	
	public String name;
	
	ValidationHelper validationHelper = new ValidationHelper();

	@GetMapping
	public String displayDashboard(Authentication request, Model model) {
		if (validationHelper.validateReturn(request)) {
			SecurityContext securityContext = SecurityContextHolder.getContext();
			if (securityContext.getAuthentication().getPrincipal() instanceof DefaultOAuth2User) {
				DefaultOAuth2User user = (DefaultOAuth2User) securityContext.getAuthentication().getPrincipal();
				model.addAttribute("userDetails",
						user.getAttribute("name") != null ? user.getAttribute("name") : user.getAttribute("login"));
//				model.addAttribute("userDetails",
//						user.getAttribute("email") != null ? user.getAttribute("email") : user.getAttribute("login"));
				name = user.getAttribute("name");
			}
				return "dashboard";
		} else {
			return "redirect:/login";
		}
		
	}
}

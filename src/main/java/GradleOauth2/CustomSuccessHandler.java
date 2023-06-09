package GradleOauth2;

import java.io.IOException;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.oauth2.client.authentication.OAuth2AuthenticationToken;
import org.springframework.security.oauth2.core.user.DefaultOAuth2User;
import org.springframework.security.web.DefaultRedirectStrategy;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.stereotype.Component;


@Component
public class CustomSuccessHandler implements AuthenticationSuccessHandler{

	@Autowired
	JwtGeneratorValidator jwtgenval;


	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			org.springframework.security.core.Authentication authentication) throws IOException, ServletException {
		// TODO Auto-generated method stub

		String redirectUrl = null;
		if(authentication.getPrincipal() instanceof DefaultOAuth2User) {
		DefaultOAuth2User  userDetails = (DefaultOAuth2User ) authentication.getPrincipal();
         String username = userDetails.getAttribute("email") !=null?userDetails.getAttribute("email"):userDetails.getAttribute("login")+"@gmail.com" ;
         if(username != null) {
        	 String token = jwtgenval.generateToken(username); 
             Date expiryDate = new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(7));
             Token tokenDetails = new Token(token, expiryDate);

        	 ((OAuth2AuthenticationToken) authentication).setDetails(tokenDetails);
        	 redirectUrl = "/dashboard";
         } 
		}
		new DefaultRedirectStrategy().sendRedirect(request, response, redirectUrl);
	}
}
	

package Package1;

import org.springframework.http.HttpHeaders;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.User;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.Cookie;

@Controller
public class Controlclass {

	@GetMapping("/")
	public String hello(HttpServletResponse response, Model model) {
		setNoCacheHeaders(response);
		Authentication authentication = SecurityContextHolder.getContext().getAuthentication();

		if (authentication != null && authentication.getPrincipal() instanceof User) {
			User user = (User) authentication.getPrincipal();
			String username = user.getUsername();
			model.addAttribute("username", username);
		}
		return "home";
	}

	@GetMapping("/login")
	public String login(HttpServletResponse response) {
		setNoCacheHeaders(response);
		return "login";
	}

	@GetMapping("/logout")
	public String logout(HttpServletRequest request, HttpServletResponse response) {
		setNoCacheHeaders(response);

		// Invalidate session and clear cookies
		HttpSession session = request.getSession(false);
		if (session != null) {
			session.invalidate();
		}
		clearCookies(request, response);
		return "redirect:/login";
	}

	@GetMapping("/user")
	public ResponseEntity<String> user() {
		return ResponseEntity.ok("You are a USER: ");
	}

	@GetMapping("/admin")
	public ResponseEntity<String> admin() {
		return ResponseEntity.ok("You are an ADMIN");
	}

	private void setNoCacheHeaders(HttpServletResponse response) {
		response.setHeader(HttpHeaders.CACHE_CONTROL, "no-cache, no-store, must-revalidate");
		response.setHeader(HttpHeaders.PRAGMA, "no-cache");
		response.setDateHeader(HttpHeaders.EXPIRES, 0);
	}

	private void clearCookies(HttpServletRequest request, HttpServletResponse response) {
		Cookie[] cookies = request.getCookies();
		if (cookies != null) {
			for (Cookie cookie : cookies) {
				if ("JSESSIONID".equals(cookie.getName())) {
					cookie.setMaxAge(0);
					cookie.setValue(null);
					cookie.setPath("/");
					response.addCookie(cookie);
				}
			}
		}
	}
}

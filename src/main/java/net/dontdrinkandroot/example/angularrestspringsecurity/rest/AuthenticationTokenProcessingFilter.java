package net.dontdrinkandroot.example.angularrestspringsecurity.rest;

import java.io.IOException;

import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;

import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.web.authentication.WebAuthenticationDetailsSource;
import org.springframework.web.filter.GenericFilterBean;


public class AuthenticationTokenProcessingFilter extends GenericFilterBean
{

	private final UserDetailsService userService;


	public AuthenticationTokenProcessingFilter(UserDetailsService userService)
	{
		this.userService = userService;
		System.out.println("=================================");
		System.out.println("Constructing AuthenticationTokenProcessingFilter...");
		System.out.println("=================================");
	}


	@Override
	public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain) throws IOException,
			ServletException
	{
		System.out.println("++++++++++++++++getting into AuthenticationTokenProcessingFilter.doFilter()++++++++++++++++");

		HttpServletRequest httpRequest = this.getAsHttpRequest(request);

		System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++");
		System.out.println(request.getAttributeNames());
		System.out.println(request.getParameterNames());
		System.out.println(request.getRemoteAddr());
		System.out.println("++++++++++++++++++++++++++++++++++++++++++++++++");

		String authToken = this.extractAuthTokenFromRequest(httpRequest);
		String userName = TokenUtils.getUserNameFromToken(authToken);

		if (userName != null) {

			UserDetails userDetails = this.userService.loadUserByUsername(userName);

			System.out.println("===========username is not null===========");

			if (TokenUtils.validateToken(authToken, userDetails)) {

				System.out.println("======================================");
				System.out.println("Token validated...");
				System.out.println("======================================");

				UsernamePasswordAuthenticationToken authentication =
						new UsernamePasswordAuthenticationToken(userDetails, null, userDetails.getAuthorities());
				authentication.setDetails(new WebAuthenticationDetailsSource().buildDetails(httpRequest));
				SecurityContextHolder.getContext().setAuthentication(authentication);
			}
		} else {
			System.out.println("========username is null=========");
		}

		System.out.println("=========go to next chain(chain.doFilter(request, response)...)===========");
		chain.doFilter(request, response);
	}


	private HttpServletRequest getAsHttpRequest(ServletRequest request)
	{
		if (!(request instanceof HttpServletRequest)) {
			throw new RuntimeException("Expecting an HTTP request");
		}

		return (HttpServletRequest) request;
	}


	private String extractAuthTokenFromRequest(HttpServletRequest httpRequest)
	{
		/* Get token from header */
		String authToken = httpRequest.getHeader("X-Auth-Token");

		/* If token not found get it from request parameter */
		if (authToken == null) {
			authToken = httpRequest.getParameter("token");
		}

		return authToken;
	}
}
package com.example.multiauthn.adapter.in.web.security;

import static java.util.Arrays.asList;
import static org.hamcrest.Matchers.endsWith;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isA;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpHeaders.LOCATION;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.model;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;

import java.util.Locale;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.MessageSource;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.web.context.WebApplicationContext;

import com.example.multiauthn.application.port.in.RegistrationUseCase;
import com.example.multiauthn.application.port.out.UserPort;
import com.example.multiauthn.domain.UserDto;

@SpringBootTest
class SecurityIntegrationTest {

	@Autowired
	private WebApplicationContext context;

	@MockBean
	private MessageSource mockMessages;

	@MockBean
	private RegistrationUseCase registrationUseCase;

	@MockBean
	private UserPort mockUserPort;

	private MockMvc mvc;

	@BeforeEach
	void setup() {
		mvc = MockMvcBuilders.webAppContextSetup(context)
				.apply(springSecurity())
				.build();
	}

	@Test
	void getLoginPage_happyPath() throws Exception {
		// Given:

		// When:
		mvc.perform(get("/login"))
				.andExpect(status().isOk())
				.andExpect(view().name("login"));

		// Then:
	}

	@Test
	void getLoginPageWithErrorAndMessage_displaysThem() throws Exception {
		// Given:
		when(mockMessages.getMessage(eq("label.test"), isNull(), isA(Locale.class)))
				.thenReturn("Test Label");

		// When:
		mvc.perform(get("/login")
				.param("messageKey", "label.test")
				.param("error", "Oh, the humanity!"))
				.andExpect(status().isOk())
				.andExpect(view().name("login"))
				.andExpect(model().attribute("message", "Test Label"))
				.andExpect(model().attribute("error", "Oh, the humanity!"));

		// Then:
	}

	@Test
	void getRegistrationPage_happyPath() throws Exception {
		// Given:

		// When:
		mvc.perform(get("/user/registration"))
				.andExpect(status().isOk())
				.andExpect(view().name("registration"));

		// Then:
	}

	@Test
	void userPage_unauthenticated() throws Exception {
		// Given:

		// When:
		mvc.perform(get("/user"))
				.andExpect(status().is3xxRedirection())
				.andExpect(header().string("Location", endsWith("/login")));
		// Then:
	}

	@Test
	void userPage_happyPath() throws Exception {
		mvc.perform(get("/user").with(user("userb").password("passb").roles("USER")))
				.andExpect(status().isOk())
				.andExpect(view().name("user"));
	}

	@Test
	void adminPage_happyPath() throws Exception {
		mvc.perform(get("/admin").with(user("admin").password("adminPass").roles("ADMIN")))
				.andExpect(status().isOk())
				.andExpect(view().name("admin"));
	}

	@Test
	void registerNewUser_happyPath() throws Exception {
		mvc.perform(post("/user/registration")
				.contentType(APPLICATION_FORM_URLENCODED)
				.param("username", "usera")
				.param("password", "passa")
				.param("firstName", "User")
				.param("lastName", "A")
				.param("matchingPassword", "passa")
				.param("email", "usera@example.com"))
				.andExpect(status().isOk())
				.andExpect(view().name("successRegister"));
	}

	@Test
	void loginBadCredentials() throws Exception {
		// Given:
		when(mockUserPort.findByUsername(eq("fbar"))).thenReturn(null);

		// When:
		mvc.perform(formLogin().user("fbar").password("qwerty"))
				.andExpect(status().is3xxRedirection())
				.andExpect(header().string(LOCATION, endsWith("/login?error=true")));

		// Then:
	}

	@Test
	void userLogin_happyPath() throws Exception {
		// Given:
		when(mockUserPort.findByUsername(eq("fbar"))).thenReturn(UserDto.builder()
				.username("fbar")
				.password("$2a$11$k9uX0rgGd8WWWYdzFHeIGuWLFZ1I5XuvbXyqelYbFXiy0/6tziq6m")
				.roles(asList("ROLE_USER"))
				.build());

		// When:
		mvc.perform(formLogin().user("fbar").password("qwerty"))
				.andExpect(status().is3xxRedirection())
				.andExpect(header().string(LOCATION, endsWith("/user")));
	}

	@Test
	void oauth2UserLogin_happyPath() throws Exception {
		// Given:
		when(mockUserPort.findByUsername(eq("fbar"))).thenReturn(UserDto.builder()
				.username("fbar")
				.password("$2a$11$k9uX0rgGd8WWWYdzFHeIGuWLFZ1I5XuvbXyqelYbFXiy0/6tziq6m")
				.roles(asList("OAUTH2_USER"))
				.build());

		// When:
		mvc.perform(formLogin().user("fbar").password("qwerty"))
				.andExpect(status().is3xxRedirection())
				.andExpect(header().string(LOCATION, endsWith("/user")));
	}

	@Test
	void adminLogin_happyPath() throws Exception {
		// Given:
		when(mockUserPort.findByUsername(eq("admin"))).thenReturn(UserDto.builder()
				.username("fbar")
				.password("$2a$11$k9uX0rgGd8WWWYdzFHeIGuWLFZ1I5XuvbXyqelYbFXiy0/6tziq6m")
				.roles(asList("ROLE_ADMIN"))
				.build());

		// When:
		mvc.perform(formLogin().user("admin").password("qwerty"))
				.andExpect(status().is3xxRedirection())
				.andExpect(header().string(LOCATION, endsWith("/admin")));
	}

	@Test
	void multiRoleUserLogin_getsHighestPage() throws Exception {
		// Given:
		when(mockUserPort.findByUsername(eq("admin"))).thenReturn(UserDto.builder()
				.username("fbar")
				.password("$2a$11$k9uX0rgGd8WWWYdzFHeIGuWLFZ1I5XuvbXyqelYbFXiy0/6tziq6m")
				.roles(asList("ROLE_USER", "ROLE_ADMIN"))
				.build());

		// When:
		mvc.perform(formLogin().user("admin").password("qwerty"))
				.andExpect(status().is3xxRedirection())
				.andExpect(header().string(LOCATION, endsWith("/admin")));
	}
}

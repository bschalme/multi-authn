package com.example.multiauthn.adapter.in.web.security;

import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
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

import java.util.Collections;
import java.util.Locale;

import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;

import com.example.multiauthn.KeycloakTestContainers;
import com.example.multiauthn.application.port.in.RegistrationUseCase;
import com.example.multiauthn.application.port.out.UserPort;
import com.example.multiauthn.domain.UserDto;

import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
class SecurityIntegrationTest extends KeycloakTestContainers {

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
	void performLoginAsUser_happyPath() throws Exception {
		// Given:

		// When:
		// Get multi-authn's /login page:
		mvc.perform(get("/login"))
				.andExpect(status().isOk());
		// Click on .../SpringBootKeycloak to select login using Keycloak, and expect a
		// redirection to Keycloak:
		MvcResult result = mvc.perform(get("/oauth2/authorization/keycloak"))
				.andExpect(status().is3xxRedirection())
				.andReturn();

		// Then:
		// Fish out the Location response header, and use that to Get the Keycloak login
		// page:
		String location = result.getResponse().getHeader(LOCATION);
		assertThat("Location header;", location, not(emptyOrNullString()));
		log.debug("Location header = %s", location);
		WebClient webclient = WebClient.builder().build();
		Mono<ResponseEntity<String>> loginPageMono = webclient.get().uri(location)
				.retrieve()
				.toEntity(String.class);

		ResponseEntity<String> loginPageResponse = loginPageMono.block();
		HttpHeaders loginPageResponseHeaders = loginPageResponse.getHeaders();
		String loginPageResponseBody = loginPageResponse.getBody();
		/*
		 * RestClient restClient = RestClient.create();
		 * ConvertibleClientHttpResponse loginPage =
		 * restClient.get().uri(location).exchange((request, response) -> {
		 * response.getHeaders().forEach((name, values) -> {
		 * values.forEach(value -> log.debug("Header '{}' = '{}'", name, value));
		 * });
		 * return response;
		 * });
		 * loginPage.getHeaders().forEach((name, values) -> {
		 * values.forEach(value -> log.debug("Header '{}' = '{}'", name, value));
		 * });
		 */
		Document loginPageDoc = Jsoup.parse(loginPageResponseBody);

		log.debug("Title = {}", loginPageDoc.title());
		Elements formTags = loginPageDoc.select("form[id=kc-form-login]");
		assertThat("Form tags;", formTags, hasSize(1));
		Element formTag = formTags.first();
		String formUrl = formTag.absUrl("action");
		log.debug("Form action = '{}'", formUrl);

		MultiValueMap<String, String> formData = new LinkedMultiValueMap<>();
		formData.put("username", Collections.singletonList("user1"));
		formData.put("password", Collections.singletonList("xsw2@WS"));

		// OK, now login:
		Mono<ResponseEntity<String>> loginResponseMono = webclient.post().uri(formUrl)
				.body(BodyInserters.fromFormData(formData))
				.retrieve()
				.onStatus(HttpStatus.BAD_REQUEST::equals,
						response -> response.bodyToMono(String.class)
								.flatMap(body -> Mono.error(new RuntimeException(body))))
				.toEntity(String.class);
		ResponseEntity<String> loginResultResponse = loginResponseMono.block();
		assertThat("HTTP Status Code after entering login credentials;",
				loginResultResponse.getStatusCode().is3xxRedirection());
		HttpHeaders loginResponseHeaders = loginResultResponse.getHeaders();
		/*
		 * String loginResponseBody =
		 * restClient.post().uri(formUrl).body("username=user1&password=xsw2@WS")
		 * .header("Content-Type",
		 * APPLICATION_FORM_URLENCODED.toString()).exchange((request, response) -> {
		 * log.debug("Response status = {}", response.getStatusCode());
		 * log.debug("Response headers = {}", response.getHeaders());
		 * return IOUtils.toString(response.getBody(), Charset.forName("UTF-8"));
		 * });
		 * log.debug("Response body: {}", loginResponseBody);
		 */
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
		mvc.perform(get("/user").with(user("user1").password("xsw2@WS").roles("user")))
		//.header(AUTHORIZATION, getUser1BearerToken()))
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

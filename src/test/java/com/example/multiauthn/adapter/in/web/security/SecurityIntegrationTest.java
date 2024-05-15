package com.example.multiauthn.adapter.in.web.security;

import static java.lang.String.format;
import static java.util.Arrays.asList;
import static org.hamcrest.MatcherAssert.assertThat;
import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.emptyOrNullString;
import static org.hamcrest.Matchers.endsWith;
import static org.hamcrest.Matchers.greaterThan;
import static org.hamcrest.Matchers.hasSize;
import static org.hamcrest.Matchers.not;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpHeaders.ACCEPT;
import static org.springframework.http.HttpHeaders.LOCATION;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.TEXT_HTML_VALUE;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestBuilders.formLogin;
import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.user;
import static org.springframework.security.test.web.servlet.setup.SecurityMockMvcConfigurers.springSecurity;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.header;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.view;
import static org.springframework.web.util.DefaultUriBuilderFactory.EncodingMode.NONE;

import java.net.URI;
import java.nio.charset.Charset;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

import org.apache.commons.io.IOUtils;
import org.apache.http.NameValuePair;
import org.apache.http.client.utils.URLEncodedUtils;
import org.jsoup.Jsoup;
import org.jsoup.nodes.Document;
import org.jsoup.nodes.Element;
import org.jsoup.select.Elements;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Disabled;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.mock.mockito.MockBean;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.web.embedded.tomcat.TomcatWebServer;
import org.springframework.context.MessageSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatusCode;
import org.springframework.http.ResponseCookie;
import org.springframework.security.oauth2.client.web.OAuth2LoginAuthenticationFilter;
import org.springframework.test.web.reactive.server.EntityExchangeResult;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.context.WebApplicationContext;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.WebClient;
import org.springframework.web.util.DefaultUriBuilderFactory;

import com.example.multiauthn.KeycloakTestContainers;
import com.example.multiauthn.application.port.in.RegistrationUseCase;
import com.example.multiauthn.application.port.out.UserPort;
import com.example.multiauthn.domain.UserDto;

import jakarta.servlet.http.Cookie;
import lombok.extern.slf4j.Slf4j;
import reactor.core.publisher.Mono;

@Slf4j
class SecurityIntegrationTest extends KeycloakTestContainers {

	@Autowired
	private WebApplicationContext context;

	@Autowired
	private WebTestClient clientForMultiAuthn;

	@LocalServerPort
	private int multiAuthnServerPort;

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
		String multiAuthnBaseUrl = format("http://localhost:%d", multiAuthnServerPort);
		log.debug("multiAuthnBaseUrl = {}", multiAuthnBaseUrl);
		/* 
		WebTestClient clientForMultiAuthn = WebTestClient.bindToServer()
				.baseUrl(multiAuthnBaseUrl).build();
				*/
		// Extract cookies from the Response:
		MultiValueMap<String, ResponseCookie> responseCookies = clientForMultiAuthn.get().uri("/login")
				.exchange()
				.expectStatus().isOk()
				.expectBody(String.class)
				.returnResult()
				.getResponseCookies();
		// Click on .../SpringBootKeycloak to select login using Keycloak, and expect a
		// redirection to Keycloak:
		EntityExchangeResult<byte[]> clickKeycloakResponse = clientForMultiAuthn.get()
				.uri(format("http://localhost:%d/oauth2/authorization/keycloak", multiAuthnServerPort))
				.exchange()
				.expectStatus().is3xxRedirection()
				.expectHeader().value(LOCATION, containsString(
						"/realms/SpringBootKeycloak/protocol/openid-connect/auth?response_type=code&client_id=multi-authn&scope=openid"))
				.expectBody()
				.returnResult();

		// Then:
		// Fish out the Location response header, and use that to Get the Keycloak login
		// page:
		assertThat("Cookies set from GET call to /oauth2/authorization/keycloak;",
				clickKeycloakResponse.getResponseCookies().size(), greaterThan(0));
		ResponseCookie clickKeycloakResponseSessionCookie = clickKeycloakResponse.getResponseCookies().get("JSESSIONID").get(0);
		Cookie jsessionidCookie = new Cookie("JSESSIONID", clickKeycloakResponseSessionCookie.getValue());
		log.debug("{} = {}", jsessionidCookie.getName(), jsessionidCookie.getValue());
		String location = clickKeycloakResponse.getResponseHeaders().get(LOCATION).get(0);
		assertThat("Location header;", location, not(emptyOrNullString()));
		log.debug("Location header = {}", location);
		MultiValueMap<String, String> fetchKeycloakLoginPageResponseCookies = new LinkedMultiValueMap<>();
		DefaultUriBuilderFactory factory = new DefaultUriBuilderFactory();
		factory.setEncodingMode(NONE);
		WebClient webclient = WebClient.builder()
		        .uriBuilderFactory(factory)
		        .build();
		String loginPageResponseBody = webclient.get().uri(location)
				.exchangeToMono(response -> {
					return response.bodyToMono(String.class)
							.flatMap(Mono::just)
							.doOnNext(ignored -> response.cookies().forEach(
									(key, respCookies) -> fetchKeycloakLoginPageResponseCookies.add(key,
											respCookies.get(0).getValue())));
				})
				.block();

		log.debug("Cookies set from fetching the Keycloak login page:");
		fetchKeycloakLoginPageResponseCookies.entrySet().stream()
				.forEach(entry -> {
					log.debug("Key = {}, Value = {}", entry.getKey(), entry.getValue());
				});

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
		MultiValueMap<String, String> kecloakPostLoginResponseCookies = new LinkedMultiValueMap<>();
		Mono<URI> loginResponseMono = webclient.post().uri(formUrl)
				.cookies(cookieMap -> {
					cookieMap.addAll(fetchKeycloakLoginPageResponseCookies);
					cookieMap.add(jsessionidCookie.getName(), jsessionidCookie.getValue());
					log.debug("Sending these cookies with the POST to login:");
					cookieMap.entrySet().stream().forEach(entry -> {
						log.debug("Key = {}, Value = {}", entry.getKey(), entry.getValue());
					});
				})
				.body(BodyInserters.fromFormData(formData))
				.exchangeToMono(response -> {
					response.cookies().forEach((key, respCookies) -> {
						if (!respCookies.isEmpty()) {
							kecloakPostLoginResponseCookies.add(key, respCookies.get(0).getValue());
						}
					});
					HttpHeaders loginResponseHeaders = response.headers().asHttpHeaders();
					HttpStatusCode statusCode = response.statusCode();
					assertThat("HTTP Status Code after entering login credentials;", statusCode.is3xxRedirection());
					log.debug("After login, Location response header = {}", loginResponseHeaders.get(LOCATION));
					List<String> locationHeaders = loginResponseHeaders.get(LOCATION);
					if (!locationHeaders.isEmpty()) {
						return Mono.just(URI.create(locationHeaders.get(0)));
					} else {
						return Mono.error(new IllegalStateException("Location header not found in response"));
					}
				});
		URI codeUri = loginResponseMono.block();
		List<NameValuePair> queryParams = URLEncodedUtils.parse(codeUri.getQuery(), Charset.forName("UTF-8"));
		log.debug("Yay! I got an authorization code!");
		String path = format("%s?%s", codeUri.getPath(), codeUri.getQuery());
		List<Cookie> cookieList = fetchKeycloakLoginPageResponseCookies.entrySet().stream()
				.map(entry -> new Cookie(entry.getKey(), entry.getValue().get(0)))
				.collect(Collectors.toList());

		 // Trade the authorization code for an access token:
		 log.debug("Trading the auth code for an access token at URL: {}", codeUri);
		 log.debug("I am going to send these cookies: {}={}", jsessionidCookie.getName(), jsessionidCookie.getValue());
		 // Thread.sleep(120000);
		 OAuth2LoginAuthenticationFilter x;
		 EntityExchangeResult<byte[]> result = clientForMultiAuthn.get().uri(codeUri)
		        .header("Sec-Fetch-Dest", "document")
		        .header("Sec-Fetch-Mode", "navigate")
		        .header("Sec-Fetch-Site", "cross-site")
		        .header("Sec-Fetch-User", "?1")
				.header("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:126.0) Gecko/20100101 Firefox/126.0")
				.cookie(jsessionidCookie.getName(), jsessionidCookie.getValue())
				.exchange()
				.expectHeader().value(LOCATION, containsString("/user"))
				.expectBody()
				.returnResult();
		String redirectAfterLogin = result.getResponseHeaders().get(LOCATION).get(0);
		result.getResponseCookies().entrySet().stream()
				.forEach(entry -> {
					log.debug("Key = {}, Value = {}", entry.getKey(), entry.getValue());
				});
		log.debug("Got the access token; now being redirected to {}", redirectAfterLogin);
		Cookie newJsessionidCookie = new Cookie("JSESSIONID", result.getResponseCookies().get("JSESSIONID").get(0).getValue());
		result = clientForMultiAuthn.get().uri(redirectAfterLogin)
				.cookie(newJsessionidCookie.getName(), newJsessionidCookie.getValue())
				.exchange()
				.expectStatus().isOk()
				.expectBody()
				.returnResult();
		log.debug("After exchanging auth code for a token, response body = {}",
				IOUtils.toString(result.getResponseBody(), "UTF8"));
		assertThat("Redirect destination after getting access token;", redirectAfterLogin, containsString("/user"));
	}

	@Test
	void getRegistrationPage_happyPath() throws Exception {
		// Given:
		TomcatWebServer x;

		// When:
		mvc.perform(get("/user/registration"))
				.andExpect(status().isOk())
				.andExpect(view().name("registration"));

		// Then:
	}

	@Test
	void userPage_unauthenticated() throws Exception {
		// When:
		EntityExchangeResult<byte[]> clickKeycloakResponse = clientForMultiAuthn.get()
				.uri("/user")
				.header(ACCEPT, TEXT_HTML_VALUE)
				.exchange()
				.expectStatus().is3xxRedirection()
				.expectHeader().value(LOCATION, endsWith("/login"))
				.expectBody()
				.returnResult();
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
	@Disabled("Need to set up a Admin user.")
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
	@Disabled("Need to set up a multi-role user.")
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

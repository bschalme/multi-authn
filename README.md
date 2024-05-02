# Multiple Authentication

This is a showcase project that demonstrates user registration and logging in. It shows how you can federate more than one source for authentication ("authn"), while have one source of truth for authorization ("authzn"). I wrote it with the intent of adapting it to other projects as required.

Much gratitude to Eugen Paraschiv and his team at [Baeldung](https://www.baeldung.com/) for their numerous tutorials that served as inspiration to this project.

## Resources

* The /login page design is based on [Bootstrap 5 Login Form with Social Login Buttons](https://bootstrapbrain.com/component/bootstrap-login-form-with-social-login-buttons/) from 
BootstrapBrain
* Set a breakpoint at `org.springframework.security.oauth2.client.authentication.OAuth2AuthorizationCodeAuthenticationProvider#authenticate` to follow the exchange
of an authorization code for an access token. Step through and step out of this method to its caller - `org.springframework.security.oauth2.client.authentication.OAuth2LoginAuthenticationProvider#authenticate` to see it setting an implementation of a fully authenticated Spring Security Authentication object.
* [OAuth2 Social Login with Spring Boot Security](https://howtodoinjava.com/spring-security/oauth2-login-with-spring-boot-security/)
  * From a search on "social login spring boot"
* [The Registration Process With Spring Security](https://www.baeldung.com/registration-with-spring-mvc-and-spring-security)
  * From a search on "spring security registration example"
* [Spring Security OAuth2](https://docs.spring.io/spring-security/reference/servlet/oauth2/index.html)
* H2 console is at /h2-console. Use this DML to see the registered users:
  * `SELECT u.userid, u.username, u.password, r.name FROM user_account u INNER JOIN user_roles ur on u.userid = ur.user_jpa_entity_userid INNER JOIN role r ON ur.roles_role_id = r.role_id`

## Running

You will need to set a bunch of OAuth2 Client IDs and secrets. Take `setenv-sample`, copy it to `setenv`, change the values in there to your own, `chmod 700 setenv`, and dot-run it:

```. ./setenv```

Then run multi-authn:

```./mvnw spring-boot:run```

Browse to [http://localhost:8080](http://localhost:8080).
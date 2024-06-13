# Multiple Authentication

This is a showcase project that demonstrates user registration and logging in. It shows how you can federate more than one source for authentication ("authn"), while have one source of truth for authorization ("authzn"). I wrote it with the intent of adapting it to other projects as required.

Much gratitude to Eugen Paraschiv and his team at [Baeldung](https://www.baeldung.com/) for their numerous tutorials that served as inspiration to this project.

## Building

1. Make sure you have a running instance of Docker available because this uses [Testcontainers](https://testcontainers.com/).
2. `./mvnw clean verify` (On Windows, go `.\mvnw clean verify`)

## Running

You will need to set a bunch of OAuth2 Client IDs and secrets. Take `setenv-sample`, copy it to `setenv`, change the values in there to your own, `chmod 700 setenv`, and dot-run it:

```. ./setenv```

Run Keycloak:

```
docker run -p 8080:8080 -e KEYCLOAK_ADMIN=admin -e KEYCLOAK_ADMIN_PASSWORD=admin \ 
--name keycloak --volume ./src/test/resources/keycloak:/opt/keycloak/data/import \
quay.io/keycloak/keycloak:25.0 start-dev --import-realm
```

Browse to Keycloak at [http://localhost:8080](http://localhost:8080), and in the realm
SpringBootKeycloak:
1. Add user user1, password xsw2@WS
2. Add that user1 to Realm role "user"
3. Create the Realm role "admin"
3. Go to Identity providers and add GitHub. You'll need to enter the Client ID and Client Secret from when you set up multi-auth as a client in GitHub, but that's it.
4. [Disable automatic user creation](https://www.keycloak.org/docs/25.0.0/server_admin/index.html#_disabling_automatic_user_creation) so that someone logging in for the first time with an external identity provider (like GitHub) does not automatically create the user in Keycloak.
    1. Otherwise this would be a bad security hole

Then in another shell, run multi-authn:

```./mvnw spring-boot:run```

Try this:
1. Browse to multi-authn at [http://localhost:8081](http://localhost:8081). Log in as user1, and you should be welcomed to the User page.
2. Log out and sign in with GitHub. Use your own GitHub credentials or your GitHub passkey to log in to GitHub. You should get bounced bck to the Keycloak login page, 
and it should be telling you you need to "Authenticate to link your account with github".
    1. Trying to log in as user1 above should give you "Invalid username or password."
3. Since you are not registered in Keycloak as a user, do so. Go to Users => Create user:
    1. Turn on "Email verified"
    2. Use the same Username you use on GitHub
    3. Provide your Email, First name, and Last name. Click Create.
    4. Go to the Credentials tab, and set a password for yourself. Turn off the Temporary switch.
    5. Go to the Role mapping tab, and click on Assign role. Change the Filter by clients drop down selection to Filter by realm roles. Assign yourself to either admin or user, or both.
4. Back at the Keyloak login screen that told you "Invalid username or password.", log in as you with the password you gave yourself.
    1. You should get a Welcome page. It will be the Administrator page if you assigned yourself the admin role, otherwise it will be the User page.
5. Logout and log back in using GitHub to sign in.
    1. Once again, you should get the same Welcome page.

## CI/CD

This project uses GitHub Actions to build and upload the generated JAR file to GitHub. See `./.github/workflows/java-ci.yml`.
* You'll need to have Multiple Authentication set up as a project in [SonarCloud](https://sonarcloud.io/).
* You'll need to set up these Repository Secrets in this GitHub repository (Settings => Secrets and variables => Actions):
    * `GH_CLIENT_ID` - your GitHub Client ID;
    * `GH_CLIENT_SECRET`; and
    * `SONAR_TOKEN` - from this project in SonarCloud.

The generated JAR file is wrapped in a ZIP file, and you can get the URL for that ZIP file from the bottom of the Summary page for the workflow run.

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

# Multiple Authentication

This is a showcase project that demonstrates user registration and logging in. It shows how you can federate more than one source for authentication ("authn"), while have one source of truth for authorization ("authzn"). I wrote it with the intent of adapting it to other projects as required.

Much gratitude to Eugen Paraschiv and his team at [Baeldung](https://www.baeldung.com/) for their numerous tutorials that served as inspiration to this project.

## Resources

* [The Registration Process With Spring Security](https://www.baeldung.com/registration-with-spring-mvc-and-spring-security)
  * From a search on "spring security registration example"
* [Spring Security OAuth2](https://docs.spring.io/spring-security/reference/servlet/oauth2/index.html)
* H2 console is at /h2-console. Use this DML to see the registered users:
  * `SELECT u.userid, u.username, u.password, r.name FROM user_account u INNER JOIN user_roles ur on u.userid = ur.user_jpa_entity_userid INNER JOIN role r ON ur.roles_role_id = r.role_id`


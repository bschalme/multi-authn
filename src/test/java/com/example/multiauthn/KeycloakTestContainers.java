package com.example.multiauthn;

import static org.springframework.boot.test.context.SpringBootTest.WebEnvironment.RANDOM_PORT;

import java.util.List;

import org.keycloak.admin.client.CreatedResponseUtil;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.boot.test.autoconfigure.web.reactive.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;

import dasniko.testcontainers.keycloak.KeycloakContainer;
import jakarta.ws.rs.core.Response;
import lombok.extern.slf4j.Slf4j;

// @Testcontainers(disabledWithoutDocker = true)
@AutoConfigureWebTestClient(timeout = "PT3M")
@SpringBootTest(webEnvironment = RANDOM_PORT)
@Slf4j
public abstract class KeycloakTestContainers {

    protected static final KeycloakContainer keycloak;
    protected static final String authServerUrl;

    static {
        keycloak = new KeycloakContainer("quay.io/keycloak/keycloak:25.0.0")
                .withRealmImportFile("keycloak/realm-export.json");
        keycloak.start();
        authServerUrl = keycloak.getAuthServerUrl();
        UserRepresentation user1 = new UserRepresentation();
        user1.setUsername("user1");
        user1.setEnabled(true);
        RealmResource springBootKeycloakRealm = keycloak.getKeycloakAdminClient().realm("SpringBootKeycloak");
        UsersResource usersResource = springBootKeycloakRealm.users();
        Response response = usersResource.create(user1);
        String user1Id = CreatedResponseUtil.getCreatedId(response);

        // Define password credential
        CredentialRepresentation passwordCred = new CredentialRepresentation();
        passwordCred.setTemporary(false);
        passwordCred.setType(CredentialRepresentation.PASSWORD);
        passwordCred.setValue("xsw2@WS");

        UserResource user1Resource = usersResource.get(user1Id);

        // Set password credential
        user1Resource.resetPassword(passwordCred);

        // Get realm role "user" (requires view-realm role)
        RoleRepresentation userRealmRole = springBootKeycloakRealm.roles()//
                .get("user").toRepresentation();

        // Assign realm role user to user1
        user1Resource.roles().realmLevel() //
                .add(List.of(userRealmRole));

        UserRepresentation admin1 = new UserRepresentation();
        admin1.setUsername("admin1");
        admin1.setEnabled(true);
        response = usersResource.create(admin1);
        passwordCred = new CredentialRepresentation();
        passwordCred.setTemporary(false);
        passwordCred.setType(CredentialRepresentation.PASSWORD);
        passwordCred.setValue("adminPass");
        UserResource admin1Resource = usersResource.get(CreatedResponseUtil.getCreatedId(response));
        admin1Resource.resetPassword(passwordCred);

        RoleRepresentation adminRole = new RoleRepresentation("admin", "Administrators", false);
        springBootKeycloakRealm.roles().create(adminRole);
        adminRole = springBootKeycloakRealm.roles().get("admin").toRepresentation();
        admin1Resource.roles().realmLevel()
                .add(List.of(adminRole));

        UserRepresentation powerUser = new UserRepresentation();
        powerUser.setUsername("powerUser");
        powerUser.setEnabled(true);
        response = usersResource.create(powerUser);
        passwordCred = new CredentialRepresentation();
        passwordCred.setTemporary(false);
        passwordCred.setType(CredentialRepresentation.PASSWORD);
        passwordCred.setValue("powerPass");
        UserResource powerUserResource = usersResource.get(CreatedResponseUtil.getCreatedId(response));
        powerUserResource.resetPassword(passwordCred);
        powerUserResource.roles().realmLevel()
                .add(List.of(userRealmRole, adminRole));

        UserRepresentation user2 = new UserRepresentation();
        user2.setUsername("user2");
        user2.setEnabled(true);
        response = usersResource.create(user2);
        passwordCred = new CredentialRepresentation();
        passwordCred.setTemporary(false);
        passwordCred.setType(CredentialRepresentation.PASSWORD);
        passwordCred.setValue("user2Pass");
        UserResource user2Resource = usersResource.get(CreatedResponseUtil.getCreatedId(response));
        user2Resource.resetPassword(passwordCred);

        // Get client
        /* 
        ClientRepresentation multiAuthnClient = springBootKeycloakRealm.clients() //
                .findByClientId("multi-authn").get(0);
        multiAuthnClient.getRedirectUris().add(format("http://localhost:%d/*", port));
        */

        // Get client level role (requires view-clients role)
        /*
        RoleRepresentation userClientRole = springBootKeycloakRealm.clients().get(multiAuthnClient.getId()) //
                .roles().get("user").toRepresentation();

        // Assign client level role to user
        user1Resource.roles() //
                .clientLevel(multiAuthnClient.getId()).add(List.of(userClientRole));
                */
    }

    @DynamicPropertySource
    static void registerResourceServerIssuerProperty(DynamicPropertyRegistry registry) {
        registry.add("spring.security.oauth2.resourceserver.jwt.issuer-uri",
                () -> authServerUrl + "/realms/SpringBootKeycloak");
        System.out.println(
                "*** Keycloak JWT Issuer URI = " + keycloak.getAuthServerUrl() + "/realms/SpringBootKeycloak");
        registry.add("spring.security.oauth2.client.provider.keycloak.issuer-uri",
                () -> authServerUrl + "/realms/SpringBootKeycloak");
/*         
        registry.add("spring.security.oauth2.client.registration.keycloak.redirect-uri",
                () -> format("http://localhost:%d/login/oauth2/code/keycloak", port));
                */
    }

    protected String getUser1BearerToken() {
        try (Keycloak keycloakAdminClient = KeycloakBuilder.builder()
                .serverUrl(keycloak.getAuthServerUrl())
                .realm("SpringBootKeycloak")
                .clientId("multi-authn")
                .username("user1")
                .password("xsw2@WS")
                .build()) {

            String access_token = keycloakAdminClient.tokenManager().getAccessToken().getToken();
            log.debug("*** Token: Bearer %s", access_token);
            return "Bearer " + access_token;
        } catch (Exception e) {
            log.error("Can't obtain an access token from Keycloak!", e);
        }
        return null;
    }
}

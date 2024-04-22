INSERT INTO role (role_id, name) VALUES (1, 'ROLE_USER');
INSERT INTO user_account (user_id, username, password, email, first_name, last_name) VALUES (1, 'fbar', 'qwerty', 'fbar@example.com', 'Foo', 'Bar');
INSERT INTO users_roles (user_id, role_id) VALUES (1, 1);

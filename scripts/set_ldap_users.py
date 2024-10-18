#!/usr/bin/env python

from ldap3 import Server, Connection, ALL, MODIFY_REPLACE
from ldap3.core.exceptions import LDAPException
import yaml
import argparse
from urllib.parse import urlparse

def create_ldap_user(user, ldap_config):
    conn = None
    try:
        # Parse the LDAP server URL
        parsed_url = urlparse(ldap_config['ldap_server'])
        host = parsed_url.hostname
        port = parsed_url.port if parsed_url.port else (636 if parsed_url.scheme == 'ldaps' else 389)
        use_ssl = parsed_url.scheme == 'ldaps'

        # Initialize the LDAP server
        server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL)

        # Bind to the server
        conn = Connection(server, user=ldap_config['bind_dn'], password=ldap_config['bind_password'], auto_bind=True)

        # DN of the new user
        dn = f"uid={user['uid']},{ldap_config['base_dn']}"

        # Build the user attributes dictionary
        attrs = {
            'objectClass': ['inetOrgPerson', 'organizationalPerson', 'person', 'kubernetesSC', 'top'],
            'uid': user['uid'],
            'cn': user['cn'],
            'sn': user['sn'],
            'mail': user.get('email', ''),
            'telephoneNumber': user.get('telephoneNumber', ''),
            'o': user.get('o', ''),
            'ou': user.get('ou', ''),
            'givenName': user.get('givenName', ''),
            'displayName': user.get('displayName', ''),
            'supplementalGroups': [str(group) for group in user.get('supplementalGroups', [])],
            'runAsUser': str(user['runAsUser']),
            'runAsGroup': str(user['runAsGroup']),
            'fsGroup': str(user['fsGroup'])
        }

        # Check if the user already exists
        if conn.search(dn, '(objectClass=*)', search_scope='BASE', attributes=['*']):
            # User exists, prepare to update
            existing_entry = conn.entries[0]
            existing_attrs = existing_entry.entry_attributes_as_dict

            modifications = {}
            for attr, new_value in attrs.items():
                existing_value = existing_attrs.get(attr, [])
                if isinstance(new_value, list):
                    new_value_set = set(new_value)
                    existing_value_set = set(existing_value)
                    if new_value_set != existing_value_set:
                        modifications[attr] = [(MODIFY_REPLACE, new_value)]
                else:
                    existing_value_single = existing_value[0] if existing_value else ''
                    if new_value != existing_value_single:
                        modifications[attr] = [(MODIFY_REPLACE, [new_value])]
            if modifications:
                if conn.modify(dn, modifications):
                    print(f"User {user['uid']} updated successfully.")
                else:
                    print(f"Failed to update user {user['uid']}: {conn.result['description']}")
            else:
                print(f"No updates necessary for user {user['uid']}.")
        else:
            # User does not exist, proceed to create
            if conn.add(dn, attributes=attrs):
                print(f"User {user['uid']} created successfully.")
            else:
                print(f"Failed to create user {user['uid']}: {conn.result['description']}")

    except LDAPException as e:
        print(f"Error in creating user {user['uid']}: {e}")
    finally:
        if conn:
            conn.unbind()

def load_users_from_yaml(path):
    with open(path, 'r') as file:
        return yaml.safe_load(file)

def main():
    parser = argparse.ArgumentParser(description='Create LDAP users from a YAML file.')
    parser.add_argument('yaml_file', help='Path to YAML file with user data')
    parser.add_argument('--ldap-server', required=True, help='LDAP server URL, e.g., ldap://localhost')
    parser.add_argument('--bind-dn', default='cn=admin,dc=example,dc=org', help='Bind DN for LDAP authentication')
    parser.add_argument('--bind-password', required=True, help='Password for Bind DN')
    parser.add_argument('--base-dn', default='ou=users,dc=example,dc=org', help='Base DN where the users will be created')

    args = parser.parse_args()

    ldap_config = {
        'ldap_server': args.ldap_server,
        'bind_dn': args.bind_dn,
        'bind_password': args.bind_password,
        'base_dn': args.base_dn,
    }

    users = load_users_from_yaml(args.yaml_file)
    for user in users['users']:
        create_ldap_user(user, ldap_config)

if __name__ == "__main__":
    main()

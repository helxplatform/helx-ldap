#!/usr/bin/env python

from ldap3 import Server, Connection, ALL, SUBTREE
import argparse
import yaml
from urllib.parse import urlparse

def fetch_user_details(ldap_server_url, bind_dn, bind_password, search_base):
    conn = None
    try:
        # Parse the LDAP server URL
        parsed_url = urlparse(ldap_server_url)
        host = parsed_url.hostname
        port = parsed_url.port
        use_ssl = parsed_url.scheme == 'ldaps'

        # Initialize the LDAP server
        server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL)
        # Bind to the server
        conn = Connection(server, user=bind_dn, password=bind_password, auto_bind=True)
        
        # Define the search parameters
        search_filter = '(objectClass=inetOrgPerson)'
        retrieve_attributes = [
            'uid', 'cn', 'sn', 'mail', 'telephoneNumber',
            'givenName', 'displayName', 'o', 'ou',
            'runAsUser', 'runAsGroup', 'fsGroup', 'supplementalGroups'  # kubernetesSC attributes
        ]

        # Perform the search
        conn.search(search_base, search_filter, search_scope=SUBTREE, attributes=retrieve_attributes)

        result_set = []
        for entry in conn.entries:
            entry_dict = entry.entry_attributes_as_dict
            processed_entry = {}
            for attr in retrieve_attributes:
                if attr in ['runAsUser', 'runAsGroup', 'fsGroup'] and attr in entry_dict:
                    # Convert single-valued integer attributes
                    processed_entry[attr] = int(entry_dict[attr][0])
                elif attr == 'supplementalGroups' and attr in entry_dict:
                    # Convert multi-valued integer attributes
                    processed_entry[attr] = [int(x) for x in entry_dict[attr]]
                else:
                    # Handle string attributes
                    processed_entry[attr] = entry_dict.get(attr, [''])[0]
            result_set.append(processed_entry)

        return result_set
    except Exception as e:
        print("LDAP error:", e)
        return []
    finally:
        if conn:
            conn.unbind()

def main():
    parser = argparse.ArgumentParser(description='Retrieve and display details for all users in the LDAP directory.')
    parser.add_argument('--ldap-server', required=True, help='LDAP server URL, e.g., ldap://localhost')
    parser.add_argument('--bind-dn', default='cn=admin,dc=example,dc=org', help='Bind DN for LDAP authentication')
    parser.add_argument('--bind-password', required=True, help='Password for Bind DN')
    parser.add_argument('--search-base', default='ou=users,dc=example,dc=org', help='Base DN where the search starts')
    parser.add_argument('--output-format', choices=['text', 'yaml'], default='text', help='Output format of the user data')

    args = parser.parse_args()

    users = fetch_user_details(args.ldap_server, args.bind_dn, args.bind_password, args.search_base)
    if args.output_format == 'yaml':
        print(yaml.dump({'users': users}, default_flow_style=False))
    else:
        for user in users:
            print("User Details:")
            for key, value in user.items():
                print(f"{key}: {value}")
            print("-" * 40)

if __name__ == "__main__":
    main()
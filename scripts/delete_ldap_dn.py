#!/usr/bin/env python

from ldap3 import Server, Connection, ALL
import argparse
from urllib.parse import urlparse

def delete_ldap_user(dn, ldap_config):
    conn = None
    try:
        # Parse the LDAP server URL
        parsed_url = urlparse(ldap_config['ldap_server'])
        host = parsed_url.hostname
        port = parsed_url.port
        use_ssl = parsed_url.scheme == 'ldaps'

        # Initialize the LDAP server
        server = Server(host, port=port, use_ssl=use_ssl, get_info=ALL)

        # Bind to the server
        conn = Connection(server, user=ldap_config['bind_dn'], password=ldap_config['bind_password'], auto_bind=True)

        # Attempt to delete the DN
        if conn.delete(dn):
            print(f"Successfully deleted DN: {dn}")
        else:
            if conn.result['description'] == 'noSuchObject':
                print(f"No such entry: {dn}")
            else:
                print(f"Error deleting DN {dn}: {conn.result['description']}")
    except Exception as e:
        print(f"LDAP error: {e}")
    finally:
        if conn:
            conn.unbind()

def main():
    parser = argparse.ArgumentParser(description='Delete a single LDAP entry specified by DN.')
    parser.add_argument('dn', help='The DN of the LDAP entry to delete')
    parser.add_argument('--ldap-server', required=True, help='LDAP server URL, e.g., ldap://localhost')
    parser.add_argument('--bind-dn', default='cn=admin,dc=example,dc=org', help='Bind DN for LDAP authentication')
    parser.add_argument('--bind-password', required=True, help='Password for Bind DN')

    args = parser.parse_args()

    ldap_config = {
        'ldap_server': args.ldap_server,
        'bind_dn': args.bind_dn,
        'bind_password': args.bind_password,
    }

    delete_ldap_user(args.dn, ldap_config)

if __name__ == "__main__":
    main()

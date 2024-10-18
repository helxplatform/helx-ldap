#!/usr/bin/env python

from ldap3 import Server, Connection, ALL, SUBTREE
import argparse
from urllib.parse import urlparse

def fetch_all_dns(ldap_server_url, bind_dn, bind_password, search_base):
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
        
        # Define the search filter; (objectClass=*) will match all entries
        search_filter = '(objectClass=*)'

        # Perform the search without requesting any attributes
        conn.search(search_base, search_filter, search_scope=SUBTREE, attributes=[])

        # Collect the DNs
        result_set = [entry.entry_dn for entry in conn.entries]
        return result_set
    except Exception as e:
        print("LDAP error:", e)
        return []
    finally:
        if conn:
            conn.unbind()

def main():
        parser = argparse.ArgumentParser(description='Retrieve all Distinguished Names (DNs) from an LDAP server.')
        parser.add_argument('--ldap-server', required=True, help='LDAP server URL, e.g., ldap://localhost')
        parser.add_argument('--bind-dn', default='cn=admin,dc=example,dc=org', help='Bind DN for LDAP authentication')
        parser.add_argument('--bind-password', required=True, help='Password for Bind DN')
        parser.add_argument('--search-base', default='dc=example,dc=org', help='Base DN where the search starts')

        args = parser.parse_args()

        # Retrieve all DNs from the LDAP server
        dns = fetch_all_dns(args.ldap_server, args.bind_dn, args.bind_password, args.search_base)
        for dn in dns:
            print(dn)

if __name__ == "__main__":
    main()

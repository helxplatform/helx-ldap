#!/usr/bin/env python

from ldap3 import Server, Connection, ALL, SUBTREE
import argparse
from urllib.parse import urlparse
import os
import yaml

# Helper function to load LDAP config from the YAML file
def load_ldap_config(config_file="helx_ldap_config.yaml"):
    if os.path.exists(config_file):
        with open(config_file, "r") as file:
            config = yaml.safe_load(file)
        return config
    else:
        return None

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
    parser.add_argument('--ldap-server', help='LDAP server URL, e.g., ldap://localhost')
    parser.add_argument('--bind-dn', help='Bind DN for LDAP authentication')
    parser.add_argument('--bind-password', help='Password for Bind DN')
    parser.add_argument('--search-base', default='dc=example,dc=org', help='Base DN where the search starts (default: dc=example,dc=org)')

    args = parser.parse_args()

    # Load the configuration from the YAML file, if it exists
    config = load_ldap_config()

    # Use values from the config file if available and not overridden by arguments
    ldap_server_url = args.ldap_server or (config['ldap'].get('server_url') if config and 'ldap' in config else None)
    bind_dn = args.bind_dn or (config['ldap']['admin'].get('bind_dn') if config and 'admin' in config['ldap'] else 'cn=admin,dc=example,dc=org')
    bind_password = args.bind_password or (config['ldap']['admin'].get('password') if config and 'admin' in config['ldap'] else None)

    # Check for missing required values
    if not ldap_server_url:
        print("Error: LDAP server URL is required.")
        return
    if not bind_password:
        print("Error: LDAP bind password is required.")
        return

    # Retrieve all DNs from the LDAP server
    dns = fetch_all_dns(ldap_server_url, bind_dn, bind_password, args.search_base)
    for dn in dns:
        print(dn)

if __name__ == "__main__":
    main()

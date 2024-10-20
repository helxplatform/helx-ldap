#!/usr/bin/env python

import os
import subprocess
import argparse

def load_ldap_config(config_file="helx_ldap_config.yaml"):
    """Load LDAP config from helx_ldap_config.yaml."""
    import yaml
    with open(config_file, "r") as file:
        return yaml.safe_load(file)

def apply_ldif_file(ldif_file, ldap_server_url, config_dn, config_password):
    """Apply a single LDIF file using ldapmodify."""
    ldapmodify_cmd = [
        "ldapmodify",
        "-H", ldap_server_url,
        "-D", config_dn,
        "-w", config_password,
        "-f", ldif_file
    ]
    
    try:
        print(f"Applying LDIF: {ldif_file}...")
        subprocess.run(ldapmodify_cmd, check=True)
        print(f"LDIF {ldif_file} applied successfully.")
    except subprocess.CalledProcessError as e:
        print(f"Error applying {ldif_file}: {e}")

def apply_ldif_directory_bottom_up(ldif_root):
    """Traverse the directory tree in a bottom-up order and apply LDIF files."""
    # Load LDAP configuration
    config = load_ldap_config()

    # Extract relevant fields from the config for config DN access
    ldap_server_url = config['ldap']['server_url']
    config_dn = config['ldap']['config']['dn']
    config_password = config['ldap']['config']['password']

    # Traverse the directory tree (bottom-up)
    for root, dirs, files in os.walk(ldif_root, topdown=False):
        for file in files:
            if file.endswith(".ldif"):
                ldif_path = os.path.join(root, file)
                apply_ldif_file(ldif_path, ldap_server_url, config_dn, config_password)

if __name__ == "__main__":
    # Argument parser setup
    parser = argparse.ArgumentParser(description="Apply LDIF files from a directory in bottom-up order.")
    parser.add_argument("directory", help="The root directory containing LDIF files to apply.")
    
    # Parse arguments
    args = parser.parse_args()

    # Apply all LDIF files in the specified directory (bottom-up)
    apply_ldif_directory_bottom_up(args.directory)

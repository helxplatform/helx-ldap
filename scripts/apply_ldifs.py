#!/usr/bin/env python

import argparse
import os
import sys
import re
from ldap3 import Server, Connection, ALL, MODIFY_ADD, MODIFY_DELETE, MODIFY_REPLACE
import ldif3

def parse_arguments():
    """
    Parse command-line arguments.

    Returns:
        argparse.Namespace: Parsed command-line arguments.
    """
    parser = argparse.ArgumentParser(description='Apply LDIF files to LDAP server.')
    parser.add_argument('ldif_directory', help='Path to the LDIF directory.')
    parser.add_argument('--ldap-server', required=True, help='LDAP server address.')
    parser.add_argument('--ldap-port', type=int, default=389, help='LDAP server port.')
    parser.add_argument('--bind-dn', default='cn=admin,dc=example,dc=org', help='Bind DN for LDAP authentication.')
    parser.add_argument('--bind-password', required=True, help='Bind password for LDAP authentication.')
    parser.add_argument('--use-ssl', action='store_true', help='Use SSL for the LDAP connection.')
    parser.add_argument('--update', action='store_true', help='Update existing entries.')
    return parser.parse_args()

def connect_ldap_server(ldap_server, ldap_port, bind_dn, bind_password, use_ssl):
    """
    Connect to the LDAP server using the provided URI and credentials.

    Args:
        ldap_server (str): The LDAP server address.
        ldap_port (int): The LDAP server port.
        bind_dn (str): The distinguished name to bind as.
        bind_password (str): The password for the bind DN.
        use_ssl (bool): Whether to use SSL.

    Returns:
        ldap3.Connection: An LDAP connection object.
    """
    try:
        server = Server(ldap_server, port=ldap_port, use_ssl=use_ssl, get_info=ALL)
        conn = Connection(server, user=bind_dn, password=bind_password, auto_bind=True)
        return conn
    except Exception as e:
        print('Failed to connect to LDAP server:', e)
        sys.exit(1)

def process_ldif_file(conn, ldif_path, update):
    print(f'Processing LDIF file: {ldif_path}')
    try:
        with open(ldif_path, 'rb') as ldif_file:
            parser = ldif3.LDIFParser(ldif_file)
            for dn_bytes, entry in parser.parse():
                if dn_bytes is None:
                    continue  # Skip empty entries

                # Check the type of dn_bytes
                if isinstance(dn_bytes, bytes):
                    dn = dn_bytes.decode('utf-8')
                else:
                    dn = dn_bytes  # Assume it's already a string

                print(f'Processing DN: {dn}')

                # Decode entry keys and values from bytes to strings
                decoded_entry = {}
                for attr_bytes, values in entry.items():
                    if isinstance(attr_bytes, bytes):
                        attr = attr_bytes.decode('utf-8')
                    else:
                        attr = attr_bytes  # Assume it's already a string
                    decoded_values = []
                    for v in values:
                        if isinstance(v, bytes):
                            v = v.decode('utf-8')
                        decoded_values.append(v)
                    decoded_entry[attr] = decoded_values
                entry = decoded_entry

                if 'changetype' in entry:
                    changetype = entry.pop('changetype')[0]
                    if changetype == 'modify':
                        process_modify(conn, dn, entry,update)
                    elif changetype == 'add':
                        process_add(conn, dn, entry)
                    elif changetype == 'delete':
                        process_delete(conn, dn)
                    else:
                        print(f'Unsupported changetype {changetype} for entry {dn}')
                else:
                    # Treat as a regular add operation
                    process_add(conn, dn, entry)
    except Exception as e:
        print(f'Error processing LDIF file {ldif_path}: {e}')

def process_add(conn, dn, entry):
    """
    Process an add operation.

    Args:
        conn (ldap3.Connection): The LDAP connection object.
        dn (str): The distinguished name of the entry.
        entry (dict): The attributes and values.
    """
    print(f'Adding entry: {dn}')
    try:
        conn.add(dn, attributes=entry)
        if conn.result['result'] == 0:
            print(f'Successfully added entry: {dn}')
        else:
            print(f'Failed to add entry {dn}: {conn.result["description"]} - {conn.result["message"]}')
    except Exception as e:
        print(f'Error adding entry {dn}: {e}')

def process_delete(conn, dn):
    """
    Process a delete operation.

    Args:
        conn (ldap3.Connection): The LDAP connection object.
        dn (str): The distinguished name of the entry.
    """
    print(f'Deleting entry: {dn}')
    try:
        conn.delete(dn)
        if conn.result['result'] == 0:
            print(f'Successfully deleted entry: {dn}')
        else:
            print(f'Failed to delete entry {dn}: {conn.result["description"]} - {conn.result["message"]}')
    except Exception as e:
        print(f'Error deleting entry {dn}: {e}')

import re  # Add this import at the top of your script

def attribute_type_exists(conn, attr_definition):
    """
    Check if an attribute type already exists in the LDAP schema.
    """
    # Extract the OID from the attribute definition
    match = re.search(r'\(\s*([0-9\.]+)', attr_definition)
    if not match:
        return False
    oid = match.group(1)
    # Search for the attribute type with the given OID
    conn.search('cn=schema,cn=config', f'(olcAttributeTypes=*{oid}*)', attributes=['olcAttributeTypes'])
    return len(conn.entries) > 0

def object_class_exists(conn, objclass_definition):
    """
    Check if an object class already exists in the LDAP schema.
    """
    # Extract the OID from the object class definition
    match = re.search(r'\(\s*([0-9\.]+)', objclass_definition)
    if not match:
        return False
    oid = match.group(1)
    # Search for the object class with the given OID
    conn.search('cn=schema,cn=config', f'(olcObjectClasses=*{oid}*)', attributes=['olcObjectClasses'])
    return len(conn.entries) > 0

def process_modify(conn, dn, entry,enable_update):
    """
    Process a modify operation.
    """
    print(f'Modifying entry: {dn}')
    modlist = []
    mod_ops = ['add', 'delete', 'replace']
    keys = list(entry.keys())
    idx = 0
    while idx < len(keys):
        mod_op = keys[idx]
        if mod_op in mod_ops:
            attrs = entry[mod_op]
            idx += 1
            for attr_name in attrs:
                if idx >= len(keys):
                    break
                attr_key = keys[idx]
                if attr_key != attr_name:
                    print(f'Expected attribute {attr_name}, but found {attr_key}')
                    break
                values = entry[attr_key]
                idx += 1
                skip_modification = False
                if mod_op == 'add' and dn == 'cn=schema,cn=config':
                    # We're modifying the schema
                    definition = values[0]
                    exists = False
                    if attr_name == 'olcAttributeTypes':
                        exists = attribute_type_exists(conn, definition)
                    elif attr_name == 'olcObjectClasses':
                        exists = object_class_exists(conn, definition)
                    if exists:
                        if enable_update:
                            print(f'{attr_name} already exists. Changing operation from add to replace.')
                            mod_op = 'replace'
                        else:
                            print(f'{attr_name} already exists. Skipping addition.')
                            skip_modification = True
                if skip_modification:
                    continue
                ldap_op = {
                    'add': MODIFY_ADD,
                    'delete': MODIFY_DELETE,
                    'replace': MODIFY_REPLACE
                }[mod_op]
                modlist.append((ldap_op, attr_name, values))
            # Skip the '-' separator if present
            if idx < len(keys) and keys[idx] == '-':
                idx += 1
        elif mod_op == '-':
            idx += 1
            continue
        else:
            print(f'Unexpected key {mod_op} in modifications for {dn}')
            idx += 1
    # Now apply the modifications
    changes = {}
    for ldap_op, attr, values in modlist:
        if attr not in changes:
            changes[attr] = []
        changes[attr].append((ldap_op, values))
    if changes:
        try:
            conn.modify(dn, changes)
            if conn.result['result'] == 0:
                print(f'Successfully modified entry: {dn}')
            elif conn.result['result'] == 20:  # LDAP error code for attributeOrValueExists
                print(f'Attribute or value already exists for {dn}, skipping modification.')
            else:
                print(f'Failed to modify entry {dn}: {conn.result["description"]} - {conn.result["message"]}')
        except Exception as e:
            print(f'Error modifying entry {dn}: {e}')
    else:
        print(f'No modifications to apply to {dn}.')


def main():
    """
    Main function to parse arguments and process LDIF files.
    """
    args = parse_arguments()
    conn = connect_ldap_server(
        ldap_server=args.ldap_server,
        ldap_port=args.ldap_port,
        bind_dn=args.bind_dn,
        bind_password=args.bind_password,
        use_ssl=args.use_ssl
    )

    for root, dirs, files in os.walk(args.ldif_directory, topdown=False):
        for file in files:
            if file.endswith('.ldif'):
                ldif_path = os.path.join(root, file)
                process_ldif_file(conn, ldif_path, args.update)
    conn.unbind()

if __name__ == '__main__':
    main()

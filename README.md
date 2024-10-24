# HELX LDAP Repository

## Overview
This repository, named **helx-ldap**, contains scripts and configuration files for 
deploying **OpenLDAP** as part of a Kubernetes infrastructure. The deployment 
focuses on handling per-user specialization within Kubernetes clusters, storing 
user information in LDAP for managing access and resource provisioning. The 
repository also includes tools for automating the generation of configuration 
files necessary for the deployment and setup of OpenLDAP.

## Contents
- Python scripts for automating the generation of configuration and Helm values
  files.
- Example configuration files that can be customized and deployed.
- Makefile for automating tasks such as generating configuration files and 
  deploying LDAP.

## Quickstart

This Quickstart guide should help you set up the administrative environment,
install and configure the LDAP server, provide connectivity to it (via 
port-forward) install extensions and configure to HeLx users, and verify
functionality by adding a test user.  Follow the steps below to get the
project up and running using the provided Makefile targets and default settings.

### Prerequisites

Ensure you have the following installed on your machine:

- **Python 3.x**
- **Helm** (for deploying OpenLDAP)
- **kubectl** (for interacting with your Kubernetes cluster)

### Step 1: Install Python Dependencies

Use pip to install the required Python packages:

```
pip install -r requirements.txt
```

### Step 2: Deploy OpenLDAP with Helm

Add the Helm repository and deploy OpenLDAP using the following Makefile 
targets:

```
make helm_add  # Add the Helm repository for OpenLDAP
make helm_deploy  # Deploy OpenLDAP to your Kubernetes cluster
```

### Step 3: Port-forward the OpenLDAP Service

Port-forward the OpenLDAP service to your local machine on port 5389:

```
kubectl port-forward svc/openldap 5389:389
```

### Step 4: Apply LDAP Overlays and Extensions

Run the following Makefile targets to set up the necessary LDAP extensions 
and overlays:

```
make apply_memberof  # Apply the memberOf overlay to OpenLDAP
make apply_kubernetes_sc  # Apply the Kubernetes security context overlay
```

### Step 5: List Existing LDAP Users

You can list the existing LDAP users with the following script:

```
./scripts/get_ldap_users.py  # This will list all users using default settings
```

### Step 6: Set New LDAP Users

To create new users from a YAML file, use the set_ldap_users.py script. 
You can find an example YAML file under test/users.yaml.

```
./scripts/set_ldap_users.py test/users.yaml
```

### Step 7: Verify the New Users

After setting new users, list them again to verify the users were created 
successfully:

```
./scripts/get_ldap_users.py  # Verify that the new users have been added
```

### Summary of Steps

1. Install dependencies: pip install -r requirements.txt
2. Add the Helm repository: make helm_add
3. Deploy OpenLDAP: make helm_deploy
4. Port-forward OpenLDAP: kubectl port-forward svc/openldap 5389:389
5. Apply the memberOf overlay: make apply_memberof
6. Apply the Kubernetes SC overlay: make apply_kubernetes_sc
7. List users: ./scripts/get_ldap_users.py
8. Add users from a YAML file: ./scripts/set_ldap_users.py test/users.yaml
9. Verify users: ./scripts/get_ldap_users.py


## Configuration Files and Scripts

### `helx_ldap_config.yaml`
The **`helx_ldap_config.yaml`** file is generated using the Python script 
`generate_helx_ldap_config.py`. It stores important LDAP-related configurations, 
including:
- **LDAP Server URL**: The address of the LDAP server.
- **Admin Bind DN**: The Distinguished Name used by the admin to bind to the 
  LDAP server for performing administrative tasks.
- **Config DN**: The DN used for accessing the `cn=config` tree, where the LDAP 
  server's internal configuration is managed.
- **Admin Password** and **Config Password**: The passwords for the admin and 
  config DNs are securely stored in this file.

This YAML file is central to both the LDAP deployment and for generating other 
necessary configuration files.

### `openldap_values.yaml`
The **`openldap_values.yaml`** file is a Helm values file used to deploy 
OpenLDAP via Helm charts. It specifies settings like:
- **Replica Count**: Number of replicas to run for OpenLDAP.
- **Admin and Config Passwords**: These are fetched from `helx_ldap_config.yaml`
  and inserted into this file for use in the OpenLDAP Helm deployment.
- **Persistence and Replication** settings to manage OpenLDAP’s data storage and 
  redundancy.

This file is generated by the Python script `generate_openldap_values.py` and 
allows the automatic deployment of OpenLDAP using Helm.

### Python Scripts
1. **`generate_helx_ldap_config.py`**: This script prompts the user for LDAP 
   configuration settings, including server URL, admin DN, config DN, and 
   optionally generates random passwords for the admin and config users. The 
   generated settings are stored in the `helx_ldap_config.yaml` file.
   
2. **`generate_openldap_values.py`**: This script reads the LDAP settings from 
   `helx_ldap_config.yaml` and generates the `openldap_values.yaml` Helm values 
   file, used for deploying OpenLDAP via a Helm chart. 

### Makefile
The **Makefile** automates several tasks in this repository, including:
- **`make openldap_values.yaml`**: Generates the Helm values file 
  (`openldap_values.yaml`) using the Python script.
- **`make clean`**: Cleans up generated files such as `helx_ldap_config.yaml` 
  and `openldap_values.yaml`.


## Automating OpenLDAP Deployment Using Helm

To deploy OpenLDAP using Helm and the values file `openldap_values.yaml`, follow 
the steps below. The Helm chart we use is referred to simply as **openldap**, 
though it originates from [Artifact Hub](https://artifacthub.io/packages/helm/helm-openldap/openldap-stack-ha).

### Prerequisites:
- **Helm** installed on your system.
- Access to a Kubernetes cluster with the proper context set.
- The `openldap_values.yaml` file generated using the scripts provided in this 
  repository.

### Steps for Deployment:

1. **Add the OpenLDAP Helm Repository**:
   Add the repository where the Helm chart is hosted:
   ```
   helm repo add openldap https://jp-gouin.github.io/helm-openldap/
   ```

2. **Update the Helm Repository**:
   Ensure you have the latest charts:
   ```
   helm repo update
   ```

3. **Deploy OpenLDAP**:
   Deploy OpenLDAP using the values file you generated:
   ```
   helm install openldap openldap/openldap-stack-ha -f openldap_values.yaml
   ```

4. **Verify the Deployment**:
   After deployment, verify the OpenLDAP pods are running:
   ```
   kubectl get pods
   ```

### Makefile support:
This process is automated by the Makefile targets `helm_repo_add` and
`helm_deploy`
```
make helm_repo_add
make helm_deploy
```

### Accessing OpenLDAP via Port-Forwarding

Once OpenLDAP is deployed in the Kubernetes cluster, you can forward the LDAP 
service port to your local machine to interact with it. By default, OpenLDAP 
uses port **389** for LDAP, but since ports below **1024** require elevated 
permissions, we will forward the service to port **5389** on your local machine.

#### Port-Forwarding the OpenLDAP Service

To allow convenient administrative local connectivity, forward the LDAP port
to **5389** locally, run the following command:

```
kubectl port-forward svc/openldap 5389:389
```

## Generic LDIF-Applying Script

The script `apply_ldif_files.py` allows you to apply multiple LDIF files in a 
specified directory in a **bottom-up** order. This is particularly useful when 
you have dependencies among your LDIF files, such as module loading or schema 
extensions, which need to be applied before the main overlay or configuration.

### Script Overview

The script uses the following steps:

1. **Load LDAP Configuration**: The LDAP configuration (such as server URL, bind 
   DN, and password) is read from the `helx_ldap_config.yaml` file.
   
2. **Directory Traversal**: The script traverses the directory tree rooted at 
   the provided directory in a bottom-up order (applying dependencies first).

3. **Apply LDIF Files**: Each `.ldif` file in the directory tree is applied to 
   the LDAP server using the `ldapmodify` command.

## Enabling the `memberOf` Overlay in OpenLDAP

The **`memberOf`** overlay in OpenLDAP provides automatic management of 
group membership information in user entries. When the overlay is enabled, 
any group membership changes (such as adding a user to a group) will 
automatically reflect in the user's `memberOf` attribute, which lists all 
groups the user is a member of.

This functionality is particularly useful for environments that frequently 
query group membership from the user entries, as it eliminates the need to 
manually track which groups a user belongs to.

## `memberOf` Overlay

To enable the `memberOf` overlay, the following steps are required:

1. **Load the `memberOf` Module**: The `memberof` module must be loaded into 
   the OpenLDAP server to make the overlay available.
   
2. Apply the memberOf Overlay: After the module is loaded, the memberOf overlay
   must be configured for the specific database where user and group entries
   are stored. The overlay ensures that the memberOf attribute is automatically
   maintained for any changes to group membership.

### Makefile support

This is automated using the `apply_memberof` target
```
make apply_memberof
```

## `kubernetesSC` user extension

The user definition (inetOrgUser) has been extended to also include a
Kubernetes SecurityContext and PodSecurityContext indended to modify a
pod on behalf of a user.  This is done with LDIF as well.

### Applying Kubernetes SC LDIFs

In addition to managing the `memberOf` overlay, the repository also includes 
LDIF files related to Kubernetes service account configuration. These LDIF 
files are located in the `ldif/kubernetesSC` directory and can be processed 
using the same generic LDIF-applying script.

### Makefile Support

The `apply_kubernetes_sc` Makefile target automates the process of applying 
these LDIF files. It uses the same generic script (`apply_ldif_files.py`) but 
starts in the `ldif/kubernetesSC` directory.
```
make apply_kubernetes_sc
```

## General Use Scripts

### `get_ldap_dn.py` Script

The `get_ldap_dn.py` script retrieves all Distinguished Names (DNs) from an 
LDAP server. It can be used to connect to an LDAP server, perform a search 
from a specified base DN, and return a list of all DNs found in that subtree.

The script accepts connection details either from the command-line arguments 
or from an optional `helx_ldap_config.yaml` file. Command-line arguments 
always take precedence over configuration values if both are provided.

#### Usage

You can run the script by specifying the LDAP server URL, bind DN, password, 
and search base either via command-line options or by using the configuration 
file:

```
scripts/get_ldap_dn.py --ldap-server <LDAP_SERVER_URL> --bind-password <BIND_PASSWORD>
```

### `delete_ldap_user.py` Script

The `delete_ldap_user.py` script is designed to delete a single LDAP entry 
specified by its Distinguished Name (DN). It connects to an LDAP server, binds 
with the provided credentials, and deletes the specified user or entry.

The script supports connection details either passed via command-line arguments 
or from an optional `helx_ldap_config.yaml` configuration file. Command-line 
arguments take precedence if both sources are provided.

#### Usage

You can run the script by specifying the DN of the entry to delete and either 
providing the LDAP server credentials via arguments or relying on the 
configuration file:

```
scripts/delete_ldap_user.py <DN> --ldap-server <LDAP_SERVER_URL> --bind-password <BIND_PASSWORD>
```

### `uuid_to_oid.py` Script

The `uuid_to_oid.py` script generates a random UUID (Universally Unique 
Identifier) and converts it to an OID (Object Identifier) in dotted decimal 
format. The UUID is generated using Python's built-in `uuid` module, and the 
OID is constructed by appending the UUID's integer representation to the prefix 
`2.25`.

This script can be used to create unique identifiers in the OID format, which 
is often used in network management, X.500 directories, and other similar 
applications.

### Usage

Run the script directly to generate a UUID and its corresponding OID:

```
scripts/uuid_to_oid.py
```

### LDAP User Retrieval Script

The `get_ldap_users.py` script retrieves and displays user details from an LDAP 
server, including group memberships. The script can output user details in 
either text or YAML format. It is intended for use in environments where LDAP 
is used for directory services and requires authentication and access to user 
data.

#### Usage

To run the script, provide connection details for the LDAP server, including 
the server URL, bind DN, and password. You can specify these details as 
command-line arguments or load them from a configuration file 
(`helx_ldap_config.yaml`).

#### Example Command

```
./scripts/get_ldap_users.py --output-format yaml
```
### LDAP User Creation Script

The `create_ldap_user.py` script allows you to create or update LDAP users 
from a YAML file and manage their group memberships. The script connects to an 
LDAP server, ensuring that users and groups are properly configured.

#### Usage

To run the script, you can either specify the necessary LDAP connection 
details via command-line arguments or use a configuration file 
(`helx_ldap_config.yaml`). Command-line arguments will take precedence 
over values in the config file.

#### Example Command

```
./scripts/create_ldap_user.py users.yaml --user-base "ou=users,dc=example,dc=org" --group-base "ou=groups,dc=example,dc=org" users.yaml
```

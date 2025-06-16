# Group Processing Hook Service Generation Prompt
## version

This is version **2.1.0**

IMPORTANT: You are delivering production-ready code. You must fully
implement code for the examples. No placeholder logic or TODOs: every
branch of the switch must compile and produce exactly the JSON shown
in each example case.

You are an experienced Go developer. Your task is to build a hook
service that integrates with an existing LDAP synchronization system.
The hook service must be implemented in Go using the Echo framework,
and include OpenAPI documentation via swaggo (ensure that the annotations
are valid and parsable by swaggo).

The hook service will be called by the main LDAP system whenever it
detects a new or changed LDAP entry. It should expose a `POST /hook`
endpoint that accepts a JSON payload containing only two fields:

- **`dn`**: a string representing the distinguished name (DN) of the
  LDAP entry.
- **`content`**: a JSON object representing the LDAP attributes of the
  entry. Single-valued attributes are strings; multi-valued are arrays.

### Payload Processing

1. **Transformation**
   Apply specialized transformation logic to the incoming payload.
   Variable expressions are indicated by `{{}}`—ask clarifying
   questions if the examples are insufficient. If the input doesn't
   correspond to any example, return `null` for `transformed`, and
   zero-length `derived` and `dependencies`. **You must fully implement**
   the transformation logic for *all* example object types. **Do not**
   leave any placeholder comments or “TODO” sections—every branch must
   be concrete Go code that reproduces the exact example behavior.

2. **Object‐Type Dispatch**
   Inspect the payload to determine its object type. Each type can
   trigger different logic. If the payload is unrecognized, log or
   skip accordingly. Each input may produce more than one output
   type.  Do not stop at the first match.  For each type whose
   entry‐criteria are met, invoke its handler and append all resulting
   transformed, derived, and dependencies entries into cumulative arrays.

3. **New Search Definitions**
   Decide whether this entry should spawn additional LDAP searches.
   Populate the `"derived"` list accordingly. All filter values in
   your derived specs **must** be constructed per RFC 4515—that is,
   code should never produce an invalid filter.

4. **Response Contract**
   Your handler must return a JSON array of 0 or more objects each
   with three keys:
   ```jsonc
   [
    {
      "transformed":  { ... }, // MAY be null if there is no change
      "derived":      [ ... ], // zero or more search specs
      "dependencies": [ ... ]  // zero or more destination DNs
    },
    {
      "transformed":  { ... }, 
      "derived":      [ ... ], 
      "dependencies": [ ... ] 
    } 
   ]
   ```
   - **`transformed`** — the final DN + attribute map to write to
     the destination LDAP.
   - **`derived`** — array of search specs, each with
     `id`, `filter`, `refresh`, `baseDN`, and `oneshot`.
   - **`dependencies`** — list of destination DNs that **must**
     exist before writing `transformed`.

5. **Processing Summary**
   Output a summary of the conversion (`transformed`, `derived`, and
   `dependencies`) for debugging. Include this summary in a README with
   instructions for customizing the transformation logic and object‑type
   handlers.

---

## Special Instructions

In addition to the procesing described above perform the following

The hook code should maintain a global pidUidMap mapping pids to uids; pids

At the start of the program the pidUidMap will contain no members, but will
accumulate pids as they are discovered from Type1 input processing.  The
corresponding uid is found in Type2 input processing.  There is a 1-1 
relationship between a pid and the corresponding uids.  Until the uid
is determined use a 0-length string as a placeholder.

In addition, the hook code should maintain and update the unc group transformation
for output Type II.  All of the pids associated with a transformed group
are extracted from the member component.  Output a Type II object the first time
all the pids associated with a group have a corresponding uid.

Also, maintain a global variable baseGid that is determined from a flag
from the application.  Assign the baseGid to all gidNumber in Type III output

Type1 input can produce both Type I and Type II output
Type2 input can produce both Type II and Type III output
Type3 input produces Type IV output

Each input may trigger a subset of Type I–IV handlers as described above,
each producing its own envelope.
Do not merge results into one object—emit one envelope per handler that fires.

## Input

There a 3 types of input to expect and are described by Type1, Type2
and Type3

### Type1 Input (UNC Group)

   {
      "dn": "cn=unc:app:renci:ordrd:{{ deployment }}:{{ groupname }},ou=Groups,dc=unc,dc=edu",
      "content": {
        "cn": "unc:app:renci:ordrd:{{ deployment }}:{{ groupname }}",
        "description": "ordrd-example, RENCI, Applications, UNC Chapel Hill",
        "isPublic": "Y",
        "member": [
          "pid=713272486,ou=people,dc=unc,dc=edu",
          "pid=709909262,ou=people,dc=unc,dc=edu",
          "pid=730294000,ou=people,dc=unc,dc=edu"
        ],
        "objectClass": [
          "groupOfNames",
          "UNCGroup"
        ],
        "owner": "ou=groups,dc=unc,dc=edu"
      }
    }

### Type2 Input (UNC User)

    {
      "dn": "pid=702390258,ou=people,dc=unc,dc=edu",
      "content": {
        "addressIsPublic": "Y",
        "c": "US",
        "cn": "Karamarie Fecho",
        "departmentNumber": "637100",
        "displayName": "Karamarie Fecho",
        "eduPersonAffiliation": [
          "member",
          "affiliate",
          "alum"
        ],
        "eduPersonEntitlement": "urn:mace:dir:entitlement:common-lib-terms",
        "eduPersonNickname": "Karamarie",
        "eduPersonPrincipalName": "kfecho@unc.edu",
        "emailIsPublic": "Y",
        "facsimileIsPublic": "Y",
        "facsimileTelephoneNumber": "(919) 967-3893",
        "gidNumber": "200",
        "givenName": "Karamarie",
        "homeDirectory": "/home/k/f/kfecho",
        "homeLocation": "cn=home-location,pid=702390258,ou=People,dc=unc,dc=edu",
        "isActive": "Y",
        "isPublic": "Y",
        "location": [
          "cn=local-location,pid=702390258,ou=People,dc=unc,dc=edu",
          "cn=alternate-work-location,pid=702390258,ou=People,dc=unc,dc=edu",
          "cn=primary-work-location,pid=702390258,ou=People,dc=unc,dc=edu"
        ],
        "loginShell": "/bin/ksh",
        "mail": "kfecho@email.unc.edu",
        "massemailallowed": "Y",
        "objectClass": [
          "posixAccount",
          "UNCPerson",
          "top",
          "UNCAccount",
          "UNCAffiliate",
          "inetOrgPerson",
          "organizationalPerson",
          "eduPerson"
        ],
        "ou": "Renaissance Computing Inst",
        "phoneIsPublic": "Y",
        "pid": "702390258",
        "postalAddress": "Chapel Hill $ Chapel Hill, NC  27516 $ USA",
        "postalCode": "27516",
        "sn": "Fecho",
        "st": "NC",
        "street": "Chapel Hill",
        "telephoneNumber": "(919) 616-2808",
        "title": "Research Collaborator",
        "uid": "kfecho",
        "uidNumber": "6651",
        "uncAccountExpired": "N",
        "uncAffiliateType": "Research Collaborator",
        "uncAssociation": "cn=association-0,pid=702390258,ou=People,dc=unc,dc=edu",
        "uncEmail": [
          "kfecho@email.unc.edu",
          "kfecho@renci.org"
        ],
        "uncPidHistory": "702390258",
        "uncPreferredSurname": "Fecho",
        "uncReverseDisplayName": "Fecho, Karamarie",
        "uncServiceTag": [
          "WWW",
          "EXPIRED",
          "KRB"
        ]
      }
    }

#### Type3 Input

Copy the posix group object to the destination, preserve the cn, but
place it in destination "ou=groups,dc=example,dc=org"

  {
    "dn": "cn=its_employee_psx,ou=PosixGroups,ou=Systems,dc=unc,dc=edu",
    "content": {
      "cn": "its_employee_psx",
      "description": "src=prop",
      "gidNumber": "200",
      "isPublic": "N",
      memberuid: [
        234,
        4350,
        9950
      ],
      "objectClass": [
        "posixGroup",
        "UNCGroup"
      ]
    }
  }


## Output

### Type I Output 

    {
      "transformed": null,
      "derived": [{
        "id": "ordrd-{{ deployment}}-{{ groupname }}-members",
        "filter": "(|(pid=713272486)(pid=709909262)(pid=730294000))",
        "refresh": 10,
        "baseDN": "ou=people,dc=unc,dc=edu",
        "oneshot": false
      }],
      dependencies: []
    }
   
### Type II Output

    {
      "transformed": {
        "dn": "cn={{ groupname }},ou=groups,dc=example,dc=org",
        "content": {
          "cn": "{{ groupname }}",
          "member": [
            "uid={{ piduidMap["713272486"] }},ou=users,dc=example,dc=org",
            "uid={{ piduidMap["709909262"] }},ou=users,dc=example,dc=org",
            "uid={{ piduidMap["730294000"] }},ou=users,dc=example,dc=org"
          ],
          "objectClass": [
            "top",
            "groupOfNames"
          ]
        }
      },
      dervied: [],
      dependencies: [
          "uid={{ piduidMap["713272486"] }},ou=users,dc=example,dc=org",
          "uid={{ piduidMap["709909262"] }},ou=users,dc=example,dc=org",
          "uid={{ piduidMap["730294000"] }},ou=users,dc=example,dc=org"
      ]
    }

### Type III Output

    {
      "transformed": {
        "dn": "uid=kfecho,ou=users,dc=example,dc=org",
        "content": {
          "cn": "Karamarie Fecho",
          "displayName": "Karamarie Fecho",
          "gidNumber": "{{ baseGid }}",
          "givenName": "Karamarie",
          "homeDirectory": "/home/{{ uid }}",
          "objectClass": [
            "top",
            "inetOrgPerson",
            "posixAccount",
            "helxUser"
          ],
          "ou": "users",
          "sn": "Fecho",
          "uid": "kfecho",
          "uidNumber": "6651",
        }
      },
      "derived": [{
        "id": "6651-posixGroups",
        "filter": "(&(objectClass=posixGroup)(memberUid=6651))"
        "refresh": 10,
        "baseDN": "dc=unc,dc=edu",
        "oneshot": false
      }],
      dependencies: []
    }


### Type IV Output

  {
    transformed: {
      "dn": "cn=its_employee_psx,ou=groups,dc=example,dc=org",
      "content": {
        "cn": "its_employee_psx",
        "description": "src=prop",
        "gidNumber": "200",
        memberuid: [
          234,
          4350,
          9950
        ],
        "objectClass": [
          "posixGroup"
        ]
      }
    },
    derived:[],
    dependencies: []
  }

---

## Application Id

The application name is ordrd-group-x
The application listens to port 5001
This is version 2.0.0

## Output

Your output should include the following artifacts:

### A. Go Source Code

1. Implement the hook service using the Echo framework.
2. Set the port to the value specified above
3. Use swaggo annotations to document the `/hook` endpoint (ensure these
   annotations are valid and can be parsed by swaggo).
4. The endpoint should accept a POST payload with "dn" and "content", apply
   the transformation as specified, validate the correctness of the filter
   and DN to catch user errors, and decide what to do based on the content
   type.
5. Return a JSON response with "transformed", "derived", and "dependencies"
   as described.
6. Clearly mark the location where the user may replace the sample
   transformation logic with their own code, but generate as much as can
   be determined from the instructions.
7. Serve Swagger UI Add e.GET("/swagger/*", echoSwagger.WrapHandler)
   so that the generated docs from `swag init` are actually exposed at `/swagger/`.


### B. Dockerfile

1. Use Go 1.23 in the build stage.
2. Use an Ubuntu base image for the final container.
3. Expose the port specified above
4. The binary name and entry point are the application name

### C. Makefile

1. Include targets for building and pushing the Docker image.
2. The main target should be named `build` and must depend on a `docs`
   target. It builds the docker image
3. The `docs` target should generate or update the Swagger docs using
   `swag init -g main.go`.
4. Accept parameters for the repository and tag, the default tag value
   should represent the version
5. The platform is linux/amd64

### D. README

1. Provide a summary of the conversion process (the "transformed" and
   "derived" elements, as well as the "dependencies") for debugging
   purposes.
2. Include instructions on how to customize the transformation logic and
   how to add additional handling for different incoming object types.
3. Include any clarifying questions or suggestions for further customization.
4. Respect the 80 character per line limit

Generate the complete code (Go source, Dockerfile, Makefile, and README)
accordingly.
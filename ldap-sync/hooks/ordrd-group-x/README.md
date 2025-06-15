# README.md

ordrd-group-x Hook Service
===========================

This service integrates with an existing LDAP sync system. It listens on
port 5001 and processes incoming LDAP entries, producing transformations
and/or derived search specs based on object type.

Conversion Process
------------------

1. **Type I (UNC Group)**
   - **Transformed**: `null`
   - **Derived**: search spec to fetch group members
   - **Dependencies**: _none_

2. **Type II (Group Creation)**
   - **Transformed**: group-of-names under
     `ou=groups,dc=example,dc=org`
   - **Derived**: _none_
   - **Dependencies**: DNs of all user entries

3. **Type III (UNC User)**
   - **Transformed**: user entry under
     `ou=users,dc=example,dc=org`
   - **Derived**: search spec for posix groups
   - **Dependencies**: _none_

4. **Type IV (Posix Group)**
   - **Transformed**: posix group under
     `ou=groups,dc=example,dc=org`
   - **Derived**: _none_
   - **Dependencies**: _none_

Customizing Transformation Logic
--------------------------------

The core handlers live in `main.go`:

- `handleType1` → UNC Group
- `handleType2` → UNC User (and triggers Type II when ready)
- `handleType3` → Posix Group

To extend:

1. Add an `isTypeX` predicate for your new payload shape.
2. Write a `handleTypeX` function mirroring existing patterns.
3. Insert it in `processPayload` above the default case.

Flags
-----

- `-baseGid string`  
  Base GID for user `gidNumber` in Type III transforms.
- `-port int` (default: 5001)  
  Listening port.

Next Steps
----------

- Adjust `groupPidMap` logic for concurrent groups if needed.
- Validate all filters and DNs per RFC 4515 to prevent injection.
- Expand error handling/logging as your use case requires.

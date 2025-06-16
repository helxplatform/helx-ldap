# ordrd-group-x Hook Service

Version: 2.1.0  
Port: 5001  

This service receives LDAP hook payloads (`POST /hook`) and emits
one or more envelopes containing:

- **transformed**: the entry (DN + content) to write (or `null`)
- **derived**: LDAP search specs for additional lookups
- **dependencies**: destination DNs that must exist first

## How It Works

1. **Type I (UNC Group)**  
   - Detects group entries by `objectClass: UNCGroup`.  
   - Emits a derived search to fetch all `pid=` members.  
   - Records `pid` → empty-UID placeholders.

2. **Type II (Group after UIDs)**  
   - Once all recorded `pid`s have real UIDs, emits a
     transformed group at `ou=groups,dc=example,dc=org`  
   - Dependencies ensure each `uid=…` exists first.

3. **Type III (UNC User)**  
   - Detects user entries by presence of `pid` and `uid`.  
   - Updates global `pidUidMap`.  
   - Emits a transformed `helxUser` under `ou=users,dc=example,dc=org`.  
   - Emits a derived search for posixGroups via `(memberUid=…)`.

4. **Type IV (Posix Group)**  
   - Copies posixGroup entries into `ou=groups,dc=example,dc=org`.  
   - Preserves only `cn`, `description`, `gidNumber`, and `memberuid`.

## Customization

- **Transformation Logic**  
  Modify or extend `isType1`, `isType2`, `isType3` in `main.go` to
  match new object criteria.  
- **Handlers**  
  Add new branches in `processHook` for additional “TypeN” cases.  
- **Flags**  
  - `--baseGid`: sets `gidNumber` for Type III outputs.

## Building & Running

```sh
# generate/update Swagger docs
make docs

# build image (defaults to linux/amd64)
make build

# push to registry
make push

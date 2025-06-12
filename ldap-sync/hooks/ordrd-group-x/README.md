ordrd-group-x Hook Service README
=================================

This service receives LDAP hook payloads at POST /hook and produces:
- transformed: final entry (DN + attributes) for destination LDAP
- derived:    additional LDAP searches (id, filter, refresh, baseDN, oneshot)
- dependencies: DNs that must exist before writing transformed entry

Usage
-----
1. Generate docs and build binary:
   make build
2. Run with optional baseGid flag:
   ./ordrd-group-x --baseGid=200
3. Send a hook payload:
   curl -X POST http://localhost:5001/hook \
     -H "Content-Type: application/json" \
     -d @payload.json

Customization
-------------
- In main.go, edit processHook(): replace or extend 
  // Example1, // Example2, // Example3 blocks.
- Add new object-type handlers for other entry types.
- Modify SearchSpec or HookResponse schemas as needed.
- Adjust flag defaults (e.g. baseGid) in init().

Extending
---------
- Add DN and filter validation in hookHandler.
- Enhance logging or integrate metrics collection.
- Add TLS or authentication middleware.

Questions & Suggestions
-----------------------
- Need support for conditional derived searches?
- Sample unit tests for each handler?
- Configurable refresh intervals in derived searches?

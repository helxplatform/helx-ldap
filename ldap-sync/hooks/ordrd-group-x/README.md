<!-- README.md -->

ordrd-group-x Hook Service (v2.0.0)

This service transforms LDAP entries into a target directory,
generates derived searches, and tracks dependencies.

Conversion summary
------------------
- **transformed**: the new DN and attributes to write, or null if
  unchanged
- **derived**: LDAP search specs (`id`, `filter`, `refresh`,
  `baseDN`, `oneshot`) for fetching related entries
- **dependencies**: DNs that must exist before writing `transformed`

Customization
-------------
1. Open **main.go**, locate the `hookHandler` function.
2. Each `if` block handles one object type (ORDRD group, UNC user,
   Posix group). To add new types, inject additional branches
   following that pattern.
3. Modify transformation logic directly under each case: build
   `TransformedObject`, `Derived`, and `Dependencies`.
4. For filter correctness, filters are constructed to follow RFC 4515.

Further suggestions
-------------------
- Integrate a full RFC 4515 filter-validator in place of the simple
  string checks.
- Add middleware for authentication or logging as needed.
- Adjust `baseGid` default via the `-baseGid` flag on startup.
- Extend `SearchSpec` with pagination or size limits if required.

Questions?
----------
- Need to support more object classes?
- Want dynamic baseDN or refresh intervals?
- Let me know any other use cases to cover.

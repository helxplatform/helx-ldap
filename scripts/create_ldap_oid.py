#!/usr/bin/env python

import uuid

def uuid_to_oid():
    # Generate a new UUID
    uid = uuid.uuid4()
    # Convert UUID to an integer and then to a dotted decimal OID string under 2.25
    oid = '2.25.' + str(uid.int)
    return oid, uid

# Generate OID and UUID
oid, new_uuid = uuid_to_oid()
print("Generated UUID:", new_uuid)
print("Corresponding OID:", oid)

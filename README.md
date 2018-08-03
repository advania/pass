# pass

This is a prototype for a password delivery system from a service provider to any users that need secrets.

This system has the downside of having credentials at rest in a recoverable way, in the database.

## TODO

* Password "masking" in the database
  * Hashing is not possible due to needing plaintext
  * Encrypting is possible but the server needs the plaintext so maybe it's useless
  * Maybe a simple way is just using base64?
* Actual CSS
* If the frontend is exposed to public, some rate limit methods should be investigated

## Goals

* As simple as possible
* As secure as possible
* Store secrets as short as possible

# pass

This is a shared secret / password delivery system that a service provider can
utilize to securely send shared secrets or password or even just text to
someone.  

The system tries to minimize the attack surface on the shared secrets by
encrypting data at rest with a token that isn't stored on the system.

## Goals

* As simple as possible
* As secure as possible
* Have secrets in plaintext as short as possible

## How?

When a shared secret is created, it gets a Version 4 UUID generated to store
it.

The UUID is used as a key for PostgreSQLs `pgp_sym_encrypt`* function to
encrypt the actual shared secret data.

But we don't want to store the decryption key right next to the data, so to
mask it from the database, we pass the uuid, along with a configurable, site
wide secret (salt?), to PostgreSQLs `hmac`* function and the argument `sha256`
and store that as our lookup key.

This way we don't store the UUID, but if we are given a UUID, we can find the
matching hmac in our database and then decrypt the secret field of the
matching row.

## Security

We focus heavily on simplicity while maintaining maximum security.

The attack surface on the shared secrets should only be around submission and
retrieval of the secrets, we have to work with plaintext secrets anyway.

Our biggest vulnerability is unnoticed frontend replacement/hijack while the
system is in active use.

Database dump/theft is a non-issue, except you can see how many secrets we are
storing, and maybe [have some fun cracking them...?
](https://security.stackexchange.com/a/93905)

### Database

The database is a little unusual for most people, our frontend user only has
the `execute` permission on our two functions, no select, insert, etc
permissions at all.

It works because those functions have the flag `security definer`* so they are
executed with the permission level of their owner, instead of their invoker.

The function owner, has ownership of the database, and so the functions run
for him.

Doing this ensures that frontend bugs or hacks can't reach the backend database
data and ensures the frontend can only use the database as-intended.

### Website

The website is written in Go, it is written to be simple but robust as
possible, a lot of the code is around handling errors gracefully and
templating.

## TODO

* Better CSS
* If the frontend is exposed to public, some rate limit methods should be
  investigated

## References

\* https://www.postgresql.org/docs/8.3/static/pgcrypto.html \
\** https://www.postgresql.org/docs/9.5/static/sql-createfunction.html

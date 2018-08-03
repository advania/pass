# pass

This is a text delivery system that someone can utilize to securely send shared
secrets or passwords or even just arbitrary text to someone else.

The system tries to minimize the attack surface on the secrets by encrypting
data at rest with a UUID that isn't stored on the system, and the UUID is only
provided to the system by a user requesting the data associated with it, and
when retrieving the data it is deleted as part of the same database query.

## Goals

Maintain project simplicity while also securely handling secrets with reversible
encryption.

## How?

When an entry is created, it gets a Version 4 UUID generated as a unique key
to find it later.

The UUID is then used as a key for PostgreSQLs `pgp_sym_encrypt`* function to
encrypt the actual secret data.

But we don't want to store the decryption key right next to the data, so to
mask it from the database, we pass the UUID, along with a salt, to PostgreSQLs
`hmac`* function and store the result as our lookup key.

By doing things this way, we don't have the decryption key for any entry unless
a request from a user provides it to us, we then pass it to `hmac` again to find
an entry that matches the same key hash, and finally using the UUID as a key, we
decrypt the payload field and return it to the requesting client.

## Security

In an ideal world to transmit a secret to someone is to have already established
a public/private key pair with them, then it is trivial to just encrypt and sign
the data and send it over any medium, but in reality, very few people have those
or even the knowledge how to use them (securely).

The attack surface on the shared secrets in this system should only be around
submission and retrieval of the secrets since we have to work with them in
plain text.

Our biggest vulnerability is unnoticed front end replacement/hijack while the
system is in active use.

Database dump/theft is a low priority problem since you need the UUID to decrypt
the payload field.

A plausible attack scenario is if an attacker can get a database backup _and_
the request/ticket between the provider and user to get the UUID and what system
that secret is for.

But then you'd have bigger issues to think about.

### Database

The front end application accesses the database with a very restricted user, it
only has `execute` permission on two stored procedures, nothing else.

It works because those functions are defined with a `security definer`* flag
which means that when they are executed, they run with the permission of their
owner, which does have more permissions.

Doing this ensures that front end bugs or exploits should not be able to attack
or dump the back end database.

### Website

The website is written in Go, it is written to be simple and robust as
possible, the majority of the code is for handling errors gracefully and
templating.

## Wrapping

The codebase is built in a way that lets you make your own program that hooks
into the request handler with `RegisterRequestHandler` et al.

The purpose is to allow templating, translation and even injection of features
without modifying the upstream code itself.

## Database creation

Run the following SQL with a superuser account before running any migration
scripts.

```sql
create user password_frontend noinherit;
create role password_owner_role;
create database passwords WITH owner = password_owner_role template = template0 lc_collate = 'C' lc_ctype = 'C';
```

And then add a corresponding entry to pg_hba.conf. Example:

```conf
host passwords password_frontend ::1/128 trust
```

Note that there is no need to have multiple databases if you intend to run
multiple instances, just use a different site secret in the config file.

## References

\* https://www.postgresql.org/docs/current/pgcrypto.html \
\** https://www.postgresql.org/docs/current/sql-createfunction.html

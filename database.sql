begin;

CREATE USER password_frontend WITH
  LOGIN
  NOSUPERUSER
  NOINHERIT
  NOCREATEDB
  NOCREATEROLE
  NOREPLICATION;

CREATE ROLE password_owner_role WITH
  NOLOGIN
  NOSUPERUSER
  INHERIT
  NOCREATEDB
  NOCREATEROLE
  NOREPLICATION;

------------------------------------------------------------------------------

CREATE DATABASE passwords
    WITH
    OWNER = password_owner_role
    ENCODING = 'UTF8'
    LC_COLLATE = 'en_US.UTF-8'
    LC_CTYPE = 'en_US.UTF-8'
    TABLESPACE = pg_default
    CONNECTION LIMIT = -1;

------------------------------------------------------------------------------

-- Table: public.passwords

-- DROP TABLE public.passwords;

CREATE TABLE public.passwords
(
    password_id uuid NOT NULL,
    password_expires timestamp without time zone NOT NULL DEFAULT (CURRENT_TIMESTAMP + ((7)::double precision * '1 day'::interval)),
    password_data text COLLATE pg_catalog."default" NOT NULL,
    CONSTRAINT passwords_pkey PRIMARY KEY (password_id)
)
WITH (
    OIDS = FALSE
)
TABLESPACE pg_default;

ALTER TABLE public.passwords
    OWNER to password_owner_role;

-- Index: password_expires_idx

-- DROP INDEX public.password_expires_idx;

CREATE INDEX password_expires_idx
    ON public.passwords USING btree
    (password_expires)
    TABLESPACE pg_default;

------------------------------------------------------------------------------

-- FUNCTION: public.create_password(uuid, text)

-- DROP FUNCTION public.create_password(uuid, text);

CREATE OR REPLACE FUNCTION public.create_password(
	pass_id uuid,
	pass_data text)
    RETURNS void
    LANGUAGE 'sql'

    COST 100
    VOLATILE SECURITY DEFINER
AS $BODY$

insert into passwords (password_id, password_data) values (pass_id, pass_data);

$BODY$;

ALTER FUNCTION public.create_password(uuid, text)
    OWNER TO password_owner_role;

GRANT EXECUTE ON FUNCTION public.create_password(uuid, text) TO password_owner_role;

GRANT EXECUTE ON FUNCTION public.create_password(uuid, text) TO password_frontend;

REVOKE ALL ON FUNCTION public.create_password(uuid, text) FROM PUBLIC;

------------------------------------------------------------------------------

-- FUNCTION: public.get_password(uuid)

-- DROP FUNCTION public.get_password(uuid);

CREATE OR REPLACE FUNCTION public.get_password(
	pass_uuid uuid)
    RETURNS text
    LANGUAGE 'sql'

    COST 100
    VOLATILE SECURITY DEFINER
AS $BODY$

-- todo migrate deletion to a seperate task? and just make the lower one exclude expired passwords
delete from passwords where password_expires <= current_timestamp;
delete from passwords where password_id = pass_uuid returning password_data;

$BODY$;

ALTER FUNCTION public.get_password(uuid)
    OWNER TO password_owner_role;

GRANT EXECUTE ON FUNCTION public.get_password(uuid) TO password_owner_role;

GRANT EXECUTE ON FUNCTION public.get_password(uuid) TO password_frontend;

REVOKE ALL ON FUNCTION public.get_password(uuid) FROM PUBLIC;

rollback;

-- For HMAC and pgp_sym_encrypt
create extension pgcrypto;

-- Table
create table passwords
(
    password_id bytea not null,
    password_expires timestamp without time zone not null,
    password_data bytea not null,
    constraint passwords_pkey primary key (password_id),
    constraint password_id_length_limit check (octet_length(password_id) = 32),
    constraint password_data_length_limit check (octet_length(password_data) < 1024),
    constraint password_expires_high_limit check (password_expires < (CURRENT_TIMESTAMP + '1 mon'::interval)),
    constraint password_expires_low_limit check (password_expires > (CURRENT_TIMESTAMP + '01:00:00'::interval))
);

alter table passwords owner to password_owner_role;
create index passwords_expire_idx on passwords (password_expires);

-- Functions / create_password
create function create_password(password_unencrypted_data text, password_expires timestamp without time zone, password_master_key text) returns uuid
    language 'plpgsql'
    volatile strict security definer
as $body$
declare pass_id uuid := gen_random_uuid();
begin

insert into passwords (password_id, password_expires, password_data)
values (
	HMAC(
		pass_id::text,
		password_master_key,
		'sha256'
	),
	password_expires,
	pgp_sym_encrypt(
		password_unencrypted_data,
		pass_id::text
	)
);

return pass_id;

end;
$body$;

alter function create_password(text, timestamp without time zone, text) owner to password_owner_role;
grant execute on function create_password(text, timestamp without time zone, text) TO password_owner_role;
grant execute on function create_password(text, timestamp without time zone, text) TO password_frontend;
revoke all on function create_password(text, timestamp without time zone, text) from public;

-- Functions / get_password
create function get_password(pass_uuid uuid, password_master_key text) RETURNS text
    language 'sql'
    volatile strict security definer
as $body$
delete from passwords where password_expires <= current_timestamp;

delete from passwords where password_id = HMAC(
	pass_uuid::text,
	password_master_key,
	'sha256'
) returning pgp_sym_decrypt(
	password_data,
	pass_uuid::text
);

$body$;

alter function get_password(uuid, text) owner to password_owner_role;
grant execute on function get_password(uuid, text) TO password_owner_role;
grant execute on function get_password(uuid, text) TO password_frontend;
revoke all on function get_password(uuid, text) from public;

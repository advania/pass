-- Remove constraints
alter table passwords drop constraint password_data_length_limit;
alter table passwords drop constraint password_expires_high_limit;
alter table passwords drop constraint password_expires_low_limit;

-- Change create_password to not take in expiry time
drop function create_password;

-- Functions / create_password
create function create_password(password_unencrypted_data text, password_master_key text) returns uuid
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
	NOW() :: timestamp + '7 days',
	pgp_sym_encrypt(
		password_unencrypted_data,
		pass_id::text
	)
);

return pass_id;

end;
$body$;

alter function create_password(text, text) owner to password_owner_role;
grant execute on function create_password(text, text) TO password_owner_role;
grant execute on function create_password(text, text) TO password_frontend;
revoke all on function create_password(text, text) from public;

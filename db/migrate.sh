#!/bin/bash

# Before Use: Set the neccessary database credentials in ~/.pgpass on your
# management user, not on the user running this application.
#
#   database.example.com:5432:*:username:password
#
# Export the following environment variables (e.g. in ~/.bash_profile):
#
#   PGHOST=database.example.com
#   PGPORT=5432
#   PGDATABASE=database
#   PGUSER=username

set -oeu pipefail

cd "${0%/*}"

PSQL="psql --single-transaction --quiet -v ON_ERROR_STOP=1"

$PSQL -c '
	SET client_min_messages TO WARNING;
	CREATE TABLE IF NOT EXISTS migrations(
		id text NOT NULL,
		PRIMARY KEY (id),
		CHECK (length(id) = 14)
	);
'

ls *.sql | awk -F. '{print $1}' | while read line; do
	if [[ 'x1' = "x$($PSQL -A -t -c 'SELECT 1 FROM migrations WHERE id = '\'$line\')" ]]; then
		# Migration already executed
		continue
	fi

	echo "[$(date '+%Y-%m-%d %H:%M:%S')] Executing migration $line"...

	$PSQL -f "$line.sql" -c 'INSERT INTO migrations (id) VALUES ('\'$line\'')'
done

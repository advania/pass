#!/bin/bash

set -oeu pipefail

cd "${0%/*}"

date=$(date '+%Y%m%d%H%M%S')
filename="$date.sql"

touch "$filename"
echo "$filename"

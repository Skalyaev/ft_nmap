#!/bin/bash
cat<<EOF > "/var/lib/postgresql/data/pg_hba.conf"
# TYPE    DATABASE    USER    ADDRESS     METHOD
local     all         all                 $AUTH_ALGO_DB
host      all         all     0.0.0.0/0   $AUTH_ALGO_DB
EOF

SOCKET="/var/run/postgresql"

psql -h $SOCKET -U "$POSTGRES_USER" -d "$POSTGRES_USER" <<-EOSQL
CREATE USER $PGUSER WITH PASSWORD '$PGPASSWORD';
CREATE DATABASE $PGDATABASE;
GRANT ALL PRIVILEGES ON DATABASE $PGDATABASE TO $PGUSER;

\c $PGDATABASE
GRANT ALL ON SCHEMA public TO $PGUSER;
EOSQL

#!/bin/sh

set -eu

required_variable() {
    variable_name=$1
    eval "variable_value=\${$variable_name:-}"
    if [ -z "$variable_value" ]; then
        echo "Required environment variable is not set: $variable_name" >&2
        exit 2
    fi
}

validate_identifier() {
    variable_name=$1
    eval "identifier=\${$variable_name}"
    case "$identifier" in
        [A-Za-z_]* ) ;;
        * )
            echo "$variable_name must start with a letter or underscore" >&2
            exit 2
            ;;
    esac
    case "$identifier" in
        *[!A-Za-z0-9_]* )
            echo "$variable_name may contain only letters, digits, and underscores" >&2
            exit 2
            ;;
    esac
}

for variable_name in \
    PGHOST \
    PGUSER \
    PGPASSWORD \
    THREATFLOW_POSTGRES_DB \
    METABASE_DB_NAME \
    METABASE_DB_USER \
    METABASE_DB_PASSWORD \
    THREATFLOW_ANALYTICS_USER \
    THREATFLOW_ANALYTICS_PASSWORD
do
    required_variable "$variable_name"
done

for variable_name in \
    PGUSER \
    THREATFLOW_POSTGRES_DB \
    METABASE_DB_NAME \
    METABASE_DB_USER \
    THREATFLOW_ANALYTICS_USER
do
    validate_identifier "$variable_name"
done

admin_database=${PGDATABASE:-postgres}

if [ "$METABASE_DB_USER" = "$PGUSER" ] || \
    [ "$THREATFLOW_ANALYTICS_USER" = "$PGUSER" ] || \
    [ "$METABASE_DB_USER" = "$THREATFLOW_ANALYTICS_USER" ]
then
    echo "Metabase, analytics, and PostgreSQL administrator roles must be distinct" >&2
    exit 2
fi

case "$METABASE_DB_NAME" in
    "$THREATFLOW_POSTGRES_DB"|airflow|postgres|template0|template1)
        echo "METABASE_DB_NAME must identify a separate application database" >&2
        exit 2
        ;;
esac

echo "Ensuring Metabase database roles and application database exist"
psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 --dbname "$admin_database" <<'SQL'
\set VERBOSITY terse
\getenv metabase_db_name METABASE_DB_NAME
\getenv metabase_db_user METABASE_DB_USER
\getenv metabase_db_password METABASE_DB_PASSWORD
\getenv analytics_user THREATFLOW_ANALYTICS_USER
\getenv analytics_password THREATFLOW_ANALYTICS_PASSWORD

SELECT format(
    'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L',
    :'metabase_db_user',
    :'metabase_db_password'
)
WHERE NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = :'metabase_db_user'
)
\gexec

SELECT format(
    'ALTER ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L',
    :'metabase_db_user',
    :'metabase_db_password'
)
\gexec

SELECT format(
    'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L',
    :'analytics_user',
    :'analytics_password'
)
WHERE NOT EXISTS (
    SELECT 1 FROM pg_roles WHERE rolname = :'analytics_user'
)
\gexec

SELECT format(
    'ALTER ROLE %I WITH LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION PASSWORD %L',
    :'analytics_user',
    :'analytics_password'
)
\gexec

SELECT format(
    'ALTER ROLE %I SET default_transaction_read_only = on',
    :'analytics_user'
)
\gexec

SELECT format(
    'CREATE DATABASE %I OWNER %I',
    :'metabase_db_name',
    :'metabase_db_user'
)
WHERE NOT EXISTS (
    SELECT 1 FROM pg_database WHERE datname = :'metabase_db_name'
)
\gexec

SELECT format(
    'ALTER DATABASE %I OWNER TO %I',
    :'metabase_db_name',
    :'metabase_db_user'
)
\gexec
SQL

echo "Ensuring the analytics role has read-only access to ThreatFlow tables"
psql --no-psqlrc --quiet --set=ON_ERROR_STOP=1 --dbname "$THREATFLOW_POSTGRES_DB" <<'SQL'
\set VERBOSITY terse
\getenv analytics_user THREATFLOW_ANALYTICS_USER
\getenv application_owner PGUSER

BEGIN;

SELECT format(
    'GRANT CONNECT ON DATABASE %I TO %I',
    current_database(),
    :'analytics_user'
)
\gexec

SELECT format(
    'GRANT USAGE ON SCHEMA public TO %I',
    :'analytics_user'
)
\gexec

SELECT format(
    'GRANT SELECT ON ALL TABLES IN SCHEMA public TO %I',
    :'analytics_user'
)
\gexec

SELECT format(
    'ALTER DEFAULT PRIVILEGES FOR ROLE %I IN SCHEMA public GRANT SELECT ON TABLES TO %I',
    :'application_owner',
    :'analytics_user'
)
\gexec

COMMIT;
SQL

echo "Metabase database roles and read-only analytics access are ready"

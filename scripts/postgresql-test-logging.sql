-- Run as the administrator of a disposable PostgreSQL 18.6 test cluster, then restart it.
-- Mirrors the application's connection privacy baseline and makes server-log tests mandatory.
ALTER SYSTEM SET log_error_verbosity = 'terse';
ALTER SYSTEM SET log_statement = 'none';
ALTER SYSTEM SET log_min_error_statement = 'panic';
ALTER SYSTEM SET log_parameter_max_length = '0';
ALTER SYSTEM SET log_parameter_max_length_on_error = '0';
ALTER SYSTEM SET logging_collector = 'on';
ALTER SYSTEM SET log_destination = 'stderr';
ALTER SYSTEM SET log_line_prefix = '%m [%p] %e ';

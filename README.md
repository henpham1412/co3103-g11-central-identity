# CO3103 Group 11 — Central Identity

Central Identity is the centralized identity and authentication service for **A Self-Hosted Learning Platform with Centralized Authentication**.

It provides a common user identity across authorized LMS instances. Each LMS instance remains responsible for its own local roles, memberships, permissions, and learning data.

## 1. Technology Stack

| Component | Version / Technology |
|---|---|
| Language | Java 25 |
| Framework | Spring Boot 4.1.1 |
| Build Tool | Apache Maven 3.9.12 via Maven Wrapper |
| Maven Wrapper | 3.3.4 (`only-script`) |
| Database | PostgreSQL 18.6 |
| Persistence | Spring Data JPA |
| Security | Spring Security and OAuth2 Resource Server |
| Validation | Spring Boot Validation |

Spring Boot manages compatible dependency versions through its dependency management. Do not add explicit versions to individual Spring Boot-managed dependencies unless required and reviewed by the team.

The agreed PostgreSQL baseline is **18.6**, as specified in DOC-07 §3.1–§3.3. Use this version for local development and integration tests.

## 2. Responsibilities

Central Identity is responsible for:

- Registering centralized user accounts.
- Authenticating users and issuing signed access tokens.
- Managing global user profiles and account status.
- Handling password recovery and password reset.
- Identifying registered LMS clients during the authentication flow.

The following responsibilities belong to each LMS instance, not Central Identity:

- LMS-specific roles (`STUDENT`, `TUTOR`, `ADMINISTRATOR`).
- Local LMS access status and class membership.
- Class, learning content, assessment, and progress records.
- LMS-specific administration and authorization.

The access token establishes the authenticated identity. It does not grant universal roles or class membership across LMS instances.

## 3. Current Development Status

The repository has been initialized with the Spring Boot project structure and its baseline dependencies.

The project is being developed incrementally. The responsibilities listed above describe the intended scope; they do not imply that every API or feature is already implemented.

The approved project documents are the source of truth for implementation:

- DOC-01 — Requirements & Use Cases
- DOC-03 — System Architecture
- DOC-04 — Database Design
- DOC-05 — API Specification

## 4. Prerequisites

Install the following software:

- **JDK 25** — Required to compile and run the application.
- **Git** — Required to clone and update the repository.
- **PostgreSQL 18.6** — Required for local development, database connectivity, and integration tests.

A separate global Maven installation is not required. The repository includes Maven Wrapper scripts that download and use the configured Maven version.

Verify the installed Java version:

```bash
java -version
javac -version
```

Both commands should report Java 25.

## 5. Getting Started

### 5.1 Clone the Repository

```bash
git clone https://github.com/henpham1412/co3103-g11-central-identity.git
cd co3103-g11-central-identity
```

Access to this private repository must be granted by the repository owner.

### 5.2 Verify Maven Wrapper

**Windows PowerShell**

```powershell
.\mvnw.cmd --version
```

**macOS / Linux**

```bash
./mvnw --version
```

The output should identify Apache Maven 3.9.12 and the Java runtime used by Maven.

On the first execution, Maven Wrapper may download the configured Maven distribution. An Internet connection is required if the distribution is not already available in the local cache.

### 5.3 Build the Project

**Windows PowerShell**

```powershell
.\mvnw.cmd -DskipTests package
```

**macOS / Linux**

```bash
./mvnw -DskipTests package
```

This verifies that the application can be compiled and packaged without executing tests. Run the test suite once the required local configuration and tests are ready.

### 5.4 Configure the Local Environment

Create a local PostgreSQL database named `central_identity_dev`, for example with
`createdb -U postgres central_identity_dev`. Flyway applies the schema migrations at startup.

PostgreSQL server logs must also protect registration PII. Every new Hikari connection sets
`log_error_verbosity=terse`, `log_statement=none`, `log_min_error_statement=panic`,
`log_parameter_max_length=0`, and `log_parameter_max_length_on_error=0`. This suppresses unique-constraint
row details and statement/parameter dumps while retaining the error header/constraint name. The JDBC
`logServerErrorDetail=false` setting separately protects application logs. Do not enable statement,
duration, sampled-query, or parameter logging for identity traffic.

For a **non-superuser application role**, a database administrator must grant the required PostgreSQL
parameter permissions once (replace `identity_app` with the configured role):

```sql
GRANT SET ON PARAMETER log_error_verbosity, log_statement, log_min_error_statement,
    log_parameter_max_length TO identity_app;
```

No superuser or server-file access is needed by the application. Missing parameter permissions prevent
pool initialization instead of silently running with unsafe logging. The last parameter,
`log_parameter_max_length_on_error`, is user-settable. Set the same privacy values in `postgresql.conf`
for other sessions using this database. PostgreSQL's server verbosity is separate from the JDBC flag;
see the [PostgreSQL 18 logging reference](https://www.postgresql.org/docs/18/runtime-config-logging.html).

The full regression suite reads **actual PostgreSQL server logs**. On a disposable PostgreSQL 18.6 test
cluster, run `psql -X -v ON_ERROR_STOP=1 -U postgres -d central_identity_dev -f scripts/postgresql-test-logging.sql`
and restart PostgreSQL. Use an administrator role confined to this disposable test cluster;
the deployed application must not receive administrator or server-file privileges.
The privacy regression fails if `logging_collector`/stderr log access is missing. It forces six concurrent
registrations through the existence check, waits for five server collision entries, and scans server,
application stdout, and application file logs for fixture emails, names, passwords, hashes, and IDs.
CI applies this setup before `./mvnw clean verify`. Locally run `.\mvnw.cmd clean verify` with JDK 25
and the test database's `DB_URL`, `DB_USERNAME`, and `DB_PASSWORD` configured.

Copy `.env.example` to `.env` (`Copy-Item .env.example .env` in PowerShell, or
`cp .env.example .env` in Bash). Set `DB_PASSWORD` to your local PostgreSQL password;
adjust `DB_URL` and `DB_USERNAME` if needed. The `.env` file is ignored by Git.
Use single quotes around values containing shell-special characters.

Spring Boot does **not** load `.env` automatically. Load its values into the same shell
used to start Maven, or configure them as environment variables in your IDE's run configuration.
The commands below support the template's single-quoted PEM values and preserve literal `\n` sequences.

**Windows PowerShell**

```powershell
Get-Content .env | ForEach-Object {
    if ($_ -match '^([A-Z_][A-Z0-9_]*)=(.*)$') {
        [Environment]::SetEnvironmentVariable($Matches[1], $Matches[2].Trim("'"), 'Process')
    }
}
```

**macOS / Linux (Bash)**

```bash
set -a
source ./.env
set +a
```

The template includes a fixed, matching **RSA 2048-bit development keypair**. Keep both keys
configured across local restarts so previously issued LMS access tokens remain verifiable until
they expire. These keys are public sample data: **never use them in production**. Use a separate,
privately managed keypair for deployments. Do not commit real passwords or signing keys.

JWTs are signed with **RS256** and include `iss` and a `kid` header. `JWT_ISSUER` defaults to
`http://localhost:8080`. Public verification keys are available without authentication at
`GET /.well-known/jwks.json`; consumers should select the key matching `kid`, allow only RS256,
and validate the configured issuer and expiration.

Set **both** `JWT_PRIVATE_KEY` (PKCS#8 PEM, `BEGIN PRIVATE KEY`) and `JWT_PUBLIC_KEY`
(X.509 PEM, `BEGIN PUBLIC KEY`) to a matching RSA pair of at least 2048 bits. PEM values may
contain real newlines or literal `\n` sequences. To create a separate keypair, generate keys outside the repository:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt-private.pem
openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem
```

Load the file contents into the corresponding environment variables. Missing, incomplete, invalid,
weak, or mismatched keys prevent startup. Local development can explicitly opt into generated keys
with `JWT_ALLOW_EPHEMERAL_KEYS=true` when neither key is configured. Restarting in that mode invalidates
existing tokens; configure persistent keys shared by all instances for deployments.
Tests explicitly enable generated keys. Existing HS256 tokens require login again.

Tokens include `sub` (the canonical UUID `user_id`), `userId`, `email`, `role`, `fullName`, and
`clientId`. The global role is `USER`; LMS roles remain local to each LMS. An omitted `clientId`
uses `central-identity` for direct login. A supplied client ID is request context, not proof of
client authentication or an authorization grant, and must be at most 100 characters without whitespace.
Tokens issued before this contract that omit `clientId` require login again.
Tokens may omit `aud` for compatibility. When present, it must be the exact string
`central-identity` or an array of nonblank strings containing that value. Foreign-only,
null, empty, or malformed audiences are rejected; `clientId` does not override this restriction.

Authentication request and response JSON uses snake_case. Registration accepts `email`, `password`,
`full_name`, and optional `client_id`, and returns `message`, `user_id`, `email`, `full_name`, and `status`.
Login accepts `email`, `password`, and optional `client_id` / `redirect_uri`. A supplied client must be
registered and active, and requires a redirect URI that exactly matches one of that client's registered URIs.
A redirect URI without a client is rejected. Omitting both selects the `central-identity` context.
Login returns `access_token`, `token_type` (`Bearer`), `expires_in` (seconds), `client_id`, and a nested
`user` containing `user_id`, `email`, `full_name`, and `status`. JWT claim names are unchanged.
Errors have exactly three members: `{"code":"BAD_REQUEST","message":"Validation failed","details":[]}`.
`details` is always an array. Validation entries use `{"field":"full_name","message":"Full name is required"}`;
lockout uses `{"locked_until":"2026-10-29T12:15:00Z"}`. Rejected values are never included.
Registration/login missing or invalid fields, malformed bodies, password policy, and invalid client/redirect
parameters return HTTP 400 / `BAD_REQUEST` on both route prefixes. Profile field validation retains
`VALIDATION_ERROR`; reset-password policy retains `PASSWORD_POLICY_VIOLATION`. Security, servlet error
dispatch, and Tomcat parser errors (including malformed percent encodings and encoded NUL paths) use
the same JSON envelope, even when the request accepts HTML.
Authentication failures, including invalid login credentials and reset tokens, return
`WWW-Authenticate: Bearer realm="central-identity"` with HTTP 401.

The failed-login policy defaults to 5 attempts and a 15-minute lockout. Configure
`auth.login.max-failed-attempts` / `AUTH_LOGIN_MAX_FAILED_ATTEMPTS` and
`auth.login.lockout-duration` / `AUTH_LOGIN_LOCKOUT_DURATION` (for example `90s` or `15m`).
Both values must be positive; invalid policy configuration prevents startup.
While the lock is active, valid login requests return HTTP 423 / `LOGIN_TEMPORARILY_LOCKED`
for both correct and incorrect passwords without checking BCrypt, changing the failure counter,
or extending the lock. Once the lock expires, password verification resumes with a fresh counter.

`JWT_EXPIRATION_MS` defaults to `86400000` (24 hours), and `JWT_REFRESH_EXPIRATION_MS`
defaults to `604800000` (7 days). Refresh token issuance is not implemented yet.

Run the JWT unit tests without a database or an environment signing key:

```powershell
.\mvnw.cmd test-compile
.\mvnw.cmd test '-Dtest=JwtServiceTest'
```

### 5.5 Run the Application

After configuring a reachable local PostgreSQL database and the corresponding Spring Boot datasource settings, run:

**Windows PowerShell**

```powershell
.\mvnw.cmd spring-boot:run
```

**macOS / Linux**

```bash
./mvnw spring-boot:run
```

The application uses `SERVER_PORT=8080` by default. Registration, login, and current-user APIs
are available at `/auth/register`, `/auth/login`, and `/users/me`, with compatible aliases under
`/api/v1`. Request bodies must be JSON objects with the documented fields and string types;
unknown fields, duplicate keys, trailing values, and implicit number/boolean-to-string conversions
are rejected before business logic. Passwords require at least 8 characters and at most 72 UTF-8 bytes.

`GET /api/v1/users/me` and `/api/v1/users/me/profile` return exactly the DOC-05 account fields
(`user_id`, `email`, `full_name`, `status`, `profile`). The optional profile is `null` when absent.
A single LEFT JOIN projection reads account and profile from one committed database snapshot,
including during concurrent PATCH. Unversioned `/users/me` and `/users/me/profile` additionally
retain `id`, `fullName`, and `role: "USER"` for compatibility; this role is not an LMS permission.
`PATCH /users/me` preserves omitted fields. Explicit `null` clears `avatar_url`, `bio`,
`phone_number`, `date_of_birth`, `locale`, or `timezone`; `full_name: null` preserves the required name.
The returned `updated_at` is the flushed profile timestamp and exactly matches the stored value.
Stored profile text rejects U+0000. `date_of_birth` must be between `1900-01-01` and today,
inclusive. These field constraints return HTTP 400 / `VALIDATION_ERROR` with field details.

Password recovery is available at `POST /auth/forgot-password` and `POST /auth/reset-password`,
including their `/api/v1/auth` aliases. Both routes are public. Forgot-password accepts `email`
and returns the same DOC-05 acknowledgement for every **accepted** request, regardless of
account existence or status. Migration V6 adds a durable PostgreSQL request/delivery queue.
Admission commits before HTTP 200; account lookup happens later. Two issuance workers are
separate from four SMTP workers. Both executors have zero in-memory backlog: when a pool is
full, unclaimed work stays in PostgreSQL. Token persistence and transition to delivery commit
atomically. SMTP never runs inside a database transaction.

Admission uses a database-wide lock and rolling 60-second budgets before account lookup, including
for unknown addresses. Defaults are 20 requests per IP, 10 per normalized email, 200 globally,
and 1,000 outstanding jobs. Configure `app.recovery.per-ip-per-minute`, `per-email-per-minute`,
`global-per-minute`, and `capacity` to fit deployment traffic. These limits are shared by all
instances using the database. Exceeding a budget returns HTTP 429 / `RECOVERY_RATE_LIMITED`;
queue capacity or database unavailability returns HTTP 503 / `RECOVERY_UNAVAILABLE`.
Both carry `Retry-After: 60` and the same generic message for existing and nonexistent accounts.
Clients should retry on these explicit responses. Account issuance still has a one-minute cooldown,
checked under its user row lock; accepted duplicates during cooldown create no additional token.
Expired admission history is pruned and is bounded by the global budget.

Set `RECOVERY_TOKEN_KEY` to a base64-encoded **32-byte cryptographically random secret** before
starting the application. Generate one with `openssl rand -base64 32`, keep it in the deployment
secret store, and share the same persistent key across instances/restarts. Do not reuse the JWT
signing key. Startup fails if this key is missing or malformed. Tokens are HMAC-SHA256 outputs
(domain-separated by `ci-password-recovery-v1:` and a random request UUID), encoded as base64url.
This lets a restarted worker reconstruct the same link without storing raw reset credentials;
only SHA-256 token hashes are stored in `password_resets`. The job stores request metadata and
a reset ID. A changed key cannot send mismatched links: the worker checks the stored hash first.
For planned rotation, pause admission at ingress, drain pending jobs (or allow issued links to
expire), and replace the secret on every instance together. Existing token hashes remain valid.

Workers poll every 250 ms. Failed issuance/delivery remains queued with exponential backoff
(2 seconds through 60 seconds); a 60-second claim lease recovers interrupted workers. Delivery
retries end when the token expires after 15 minutes; expiry cleanup logs the undelivered count.
Delivery is at least once: SMTP acceptance followed by a connection/process failure can produce
a duplicate of the same link. Monitor queued job age/count and the retry/expiry warnings.

`ip_requested` preserves the initiating client address through queueing and retries. By default
all forwarding headers are ignored. Set `RECOVERY_TRUSTED_PROXIES` to a comma-separated list of
managed proxy IPs/CIDRs only. The resolver walks all `X-Forwarded-For` values from right to left,
stopping at the first untrusted hop, and accepts numeric IP literals only. Ingress must overwrite
or correctly append the actual peer to incoming X-Forwarded-For. Keep
`server.forward-headers-strategy=none` so container/framework rewriting cannot bypass this trust
boundary. `Forwarded` and `X-Real-IP` do not override it. Avoid trusting entire client networks.

Configure `app.reset-password.base-url`
(`APP_RESET_PASSWORD_BASE_URL` in the environment); it defaults to
`http://localhost:3000/reset-password`. Links have the form `<base-url>?token=<token>`.
Set `MAIL_USERNAME` to the sending Gmail address and `MAIL_PASSWORD` to its app password.
`spring.mail` in `application.yaml` defaults to `smtp.gmail.com:587`, SMTP authentication,
required STARTTLS, certificate hostname verification, and five-second connection/read/write timeouts.
`MAIL_HOST` and `MAIL_PORT` can select another SMTP provider; Spring's `spring.mail` properties
can override the remaining settings. SMTP debug output is disabled. Do not commit mail credentials.
Recovery logs contain job IDs and exception types only, never tokens, links, passwords,
message bodies, or transport exception contents.

Tests activate the `test` profile and replace SMTP with `InMemoryMailSender`, a thread-safe mailbox
under `src/test/java` that is excluded from the production JAR. Tests and audit probes can autowire
it and inspect `getMessages()` for recipient, sender, subject, and reset link, then `clear()` it.
No external SMTP credentials are needed. A separate `smtp-test` fixture uses the production
JavaMailSender against a loopback SMTP server with the default 5-second timeouts; TLS/authentication
are disabled only for this fixture. Other recovery HTTP tests extract their tokens
from this mailbox and verify commit/rollback behavior, delivery failures, and credential log hygiene.

Only ACTIVE users receive a token. Tokens expire after 15 minutes and are stored only as SHA-256 hashes.
Reset-password accepts `token`
and `new_password`, uses the configured BCrypt encoder, and consumes the token atomically with
the password update. Row locks prevent concurrent token reuse and password overwrites by login.
Migration V5 adds `used_at`; legacy `is_used` flags remain authoritative for previously consumed tokens.
Unknown, expired, or consumed tokens all return HTTP 401 with code `INVALID_OR_EXPIRED_RESET_TOKEN`
and message `Invalid or expired password reset token`. Invalid recovery emails return HTTP 400 /
`BAD_REQUEST`; reset password policy failures return HTTP 400 / `PASSWORD_POLICY_VIOLATION`.
Other DTO validation errors retain `VALIDATION_ERROR`. Existing JWTs remain valid until expiration.

## 6. Maven Wrapper Configuration

The repository uses the following settings in `.mvn/wrapper/maven-wrapper.properties`:

```properties
wrapperVersion=3.3.4
distributionType=only-script
distributionUrl=https://repo.maven.apache.org/maven2/org/apache/maven/apache-maven/3.9.12/apache-maven-3.9.12-bin.zip
```

- `wrapperVersion` identifies the Maven Wrapper version.
- `distributionType=only-script` uses the lightweight wrapper scripts without requiring `maven-wrapper.jar`.
- `distributionUrl` specifies the Apache Maven distribution to use.

Keep the wrapper scripts and configuration committed to version control so all team members use the same Maven distribution. Do not modify these settings locally unless the team agrees to update the shared configuration.

## 7. API Scope

The planned Central Identity API contract in DOC-05 includes:

| Method | Endpoint | Purpose |
|---|---|---|
| `POST` | `/auth/register` | Register a centralized account |
| `POST` | `/auth/login` | Authenticate and issue an access token |
| `POST` | `/auth/forgot-password` | Start password recovery |
| `POST` | `/auth/reset-password` | Reset a password |
| `GET` | `/users/me` | Retrieve the current user's profile |
| `PATCH` | `/users/me` | Update the current user's profile |

These endpoints are part of the planned API contract and should be considered implemented only when the corresponding functionality is available in the source code.

## 8. Development Conventions

- Follow the repository's protected `main` branch and Pull Request review workflow.
- Use feature branches for development.
- Keep API contracts aligned with DOC-05.
- Keep database entities and relationships aligned with DOC-04.
- Update the relevant documentation when an agreed design or API contract changes.
- Run the available build and test checks before submitting a Pull Request.

## 9. Project Documentation

Detailed requirements, design, and implementation contracts are maintained in the group's shared documentation:

- DOC-01 — Requirements & Use Cases
- DOC-02 — UI/UX Design
- DOC-03 — System Architecture
- DOC-04 — Database Design
- DOC-05 — API Specification
- DOC-06 — Adaptive Learning Design
- DOC-07 — Development Setup

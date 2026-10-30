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
| Database | PostgreSQL |
| Persistence | Spring Data JPA |
| Security | Spring Security and OAuth2 Resource Server |
| Validation | Spring Boot Validation |

Spring Boot manages compatible dependency versions through its dependency management. Do not add explicit versions to individual Spring Boot-managed dependencies unless required and reviewed by the team.

The PostgreSQL major version and local connection configuration will be standardized as part of the development setup.

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
- **PostgreSQL** — Required when running the application with database connectivity enabled.

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

### 5.4 Configure the Database

The service uses PostgreSQL. Each developer should use a local development database rather than relying on another developer's local database.

The exact database name, connection settings, and schema migration workflow will be documented after the team finalizes the local database setup.

Do not commit local database passwords, signing keys, or other secrets to the repository. Keep machine-specific configuration separate from shared project files.

JWTs are signed with **RS256** and include `iss` and a `kid` header. `JWT_ISSUER` defaults to
`http://localhost:8080`. Public verification keys are available without authentication at
`GET /.well-known/jwks.json`; consumers should select the key matching `kid`, allow only RS256,
and validate the configured issuer and expiration.

Set **both** `JWT_PRIVATE_KEY` (PKCS#8 PEM, `BEGIN PRIVATE KEY`) and `JWT_PUBLIC_KEY`
(X.509 PEM, `BEGIN PUBLIC KEY`) to a matching RSA pair of at least 2048 bits. PEM values may
contain real newlines or literal `\n` sequences. For example, generate keys outside the repository:

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out jwt-private.pem
openssl pkey -in jwt-private.pem -pubout -out jwt-public.pem
```

Load the file contents into the corresponding environment variables. If neither key is configured,
the service generates an ephemeral pair at startup for local development. Restarting then invalidates
existing tokens; configure persistent keys shared by all instances for deployments. Incomplete,
invalid, weak, or mismatched configured keys prevent startup. Existing HS256 tokens require login again.

`JWT_EXPIRATION_MS` defaults to `86400000` (24 hours), and `JWT_REFRESH_EXPIRATION_MS`
defaults to `604800000` (7 days). Refresh token issuance is not implemented yet.

Run the JWT unit tests without a database or an environment signing key:

```powershell
.\mvnw.cmd test '-Dtest=JwtServiceTest' '-Dmaven.compiler.release=24'
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

The application will start on the configured server port. The port and API base path will be documented once the application configuration is finalized.

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

package vn.edu.hcmut.co3103.identity;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.dao.DataIntegrityViolationException;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

@SpringBootTest
class UserStatusMigrationIntegrationTest {

    @Autowired
    private DataSource dataSource;
    @Autowired
    private JdbcTemplate jdbcTemplate;

    @ParameterizedTest
    @ValueSource(booleans = {false, true})
    void upgradesV2WithOrWithoutLegacyUsersAndRejectsUnsupportedStatuses(boolean hasLegacyUsers) {
        // Only a generated identifier is interpolated; all user data is bound as parameters.
        String schema = "status_migration_" + UUID.randomUUID().toString().replace("-", "");
        String usersTable = schema + ".users";
        try {
            Flyway previous = Flyway.configure().dataSource(dataSource).schemas(schema)
                    .defaultSchema(schema).target("2").load();
            previous.migrate();
            var history = jdbcTemplate.queryForList("SELECT version, checksum FROM " + schema
                    + ".flyway_schema_history WHERE version IN ('1', '2') ORDER BY installed_rank");
            assertThat(history).hasSize(2);

            List<String> allowedStatuses = List.of("ACTIVE", "SUSPENDED", "DEACTIVATED");
            for (String status : allowedStatuses) {
                insertUser(usersTable, status, status);
            }
            if (hasLegacyUsers) {
                insertUser(usersTable, "legacy", "INACTIVE");
            }

            Flyway latest = Flyway.configure().dataSource(dataSource).schemas(schema)
                    .defaultSchema(schema).load();
            assertThat(latest.migrate().migrationsExecuted).isEqualTo(1);
            assertThat(latest.info().current().getVersion().getVersion()).isEqualTo("3");
            latest.validate();
            assertThat(jdbcTemplate.queryForList("SELECT version, checksum FROM " + schema
                    + ".flyway_schema_history WHERE version IN ('1', '2') ORDER BY installed_rank"))
                    .isEqualTo(history);
            assertThat(jdbcTemplate.queryForObject("SELECT COUNT(*) FROM " + usersTable, Integer.class))
                    .isEqualTo(hasLegacyUsers ? 4 : 3);
            for (String status : allowedStatuses) {
                assertThat(jdbcTemplate.queryForObject("SELECT status FROM " + usersTable + " WHERE email = ?",
                        String.class, status + "@example.com")).isEqualTo(status);
                insertUser(usersTable, "after-" + status, status);
            }
            if (hasLegacyUsers) {
                assertThat(jdbcTemplate.queryForObject("SELECT status FROM " + usersTable + " WHERE email = ?",
                        String.class, "legacy@example.com")).isEqualTo("DEACTIVATED");
            }
            for (String status : List.of("INACTIVE", "UNKNOWN")) {
                var insertError = assertThrows(DataIntegrityViolationException.class,
                        () -> insertUser(usersTable, "rejected-" + status, status));
                assertThat(insertError.getMostSpecificCause()).hasMessageContaining("chk_users_status");
                var updateError = assertThrows(DataIntegrityViolationException.class,
                        () -> jdbcTemplate.update("UPDATE " + usersTable + " SET status = ? WHERE email = ?",
                                status, "ACTIVE@example.com"));
                assertThat(updateError.getMostSpecificCause()).hasMessageContaining("chk_users_status");
            }
        } finally {
            jdbcTemplate.execute("DROP SCHEMA IF EXISTS " + schema + " CASCADE");
        }
    }

    private void insertUser(String usersTable, String name, String status) {
        jdbcTemplate.update("INSERT INTO " + usersTable
                        + " (user_id, email, password_hash, full_name, status) VALUES (?, ?, ?, ?, ?)",
                UUID.randomUUID(), name + "@example.com", "migration-test-hash", "Migration Test", status);
    }
}

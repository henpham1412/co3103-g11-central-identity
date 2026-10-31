package vn.edu.hcmut.co3103.identity;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.core.io.ClassPathResource;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.datasource.init.ResourceDatabasePopulator;

import javax.sql.DataSource;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class PasswordResetMigrationIntegrationTest {

    @Autowired
    private DataSource dataSource;
    @Autowired
    private JdbcTemplate jdbc;

    @Test
    void upgradesV3WithBothIndexesAndAllowsIndexScriptToRunAgain() throws Exception {
        String schema = "password_reset_migration_" + UUID.randomUUID().toString().replace("-", "");
        try {
            Flyway.configure().dataSource(dataSource).schemas(schema).defaultSchema(schema).target("3").load().migrate();
            var history = jdbc.queryForList("SELECT version, checksum FROM " + schema
                    + ".flyway_schema_history WHERE version IN ('1', '2', '3') ORDER BY installed_rank");
            UUID userId = UUID.randomUUID();
            jdbc.update("INSERT INTO " + schema + ".users (user_id, email, password_hash, full_name) VALUES (?, ?, ?, ?)",
                    userId, "migration@example.com", "test-hash", "Migration Test");
            jdbc.update("INSERT INTO " + schema
                            + ".password_resets (reset_id, user_id, token_hash, expires_at, is_used)"
                            + " VALUES (?, ?, ?, CURRENT_TIMESTAMP + INTERVAL '15 minutes', TRUE)",
                    UUID.randomUUID(), userId, "existing-token-hash");

            var flyway = Flyway.configure().dataSource(dataSource).schemas(schema).defaultSchema(schema).target("4").load();
            assertThat(flyway.migrate().migrationsExecuted).isEqualTo(1);
            flyway.validate();
            assertThat(jdbc.queryForList("SELECT version, checksum FROM " + schema
                    + ".flyway_schema_history WHERE version IN ('1', '2', '3') ORDER BY installed_rank")).isEqualTo(history);
            assertThat(jdbc.queryForObject("SELECT is_used FROM " + schema + ".password_resets WHERE token_hash = ?",
                    Boolean.class, "existing-token-hash")).isTrue();

            try (var connection = dataSource.getConnection()) {
                String originalSchema = connection.getSchema();
                try {
                    connection.setSchema(schema);
                    new ResourceDatabasePopulator(new ClassPathResource("db/migration/V4__add_password_resets_indexes.sql"))
                            .populate(connection);
                } finally {
                    connection.setSchema(originalSchema);
                }
            }
            var indexes = jdbc.queryForList("SELECT indexname FROM pg_indexes WHERE schemaname = ?"
                            + " AND tablename = 'password_resets' AND indexname IN"
                            + " ('idx_password_resets_user_id', 'idx_password_resets_expires_at')",
                    String.class, schema);
            assertThat(indexes).containsExactlyInAnyOrder("idx_password_resets_user_id", "idx_password_resets_expires_at");
            assertThat(jdbc.queryForObject("SELECT indexdef FROM pg_indexes WHERE schemaname = ?"
                            + " AND indexname = 'idx_password_resets_user_id'", String.class, schema))
                    .contains("(user_id)");
            assertThat(jdbc.queryForObject("SELECT indexdef FROM pg_indexes WHERE schemaname = ?"
                            + " AND indexname = 'idx_password_resets_expires_at'", String.class, schema))
                    .contains("(expires_at)");
            assertThat(flyway.migrate().migrationsExecuted).isZero();
        } finally {
            // The schema name is generated locally, never derived from request data.
            jdbc.execute("DROP SCHEMA IF EXISTS " + schema + " CASCADE");
        }
    }
}

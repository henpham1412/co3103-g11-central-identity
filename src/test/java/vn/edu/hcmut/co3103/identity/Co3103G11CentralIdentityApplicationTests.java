package vn.edu.hcmut.co3103.identity;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.JdbcTemplate;

import static org.junit.jupiter.api.Assertions.assertEquals;

@SpringBootTest
class Co3103G11CentralIdentityApplicationTests {

	@Test
	void contextLoads() {
	}

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @Test
    void flywayMigrationCreatesExpectedTables() {
        Integer tableCount = jdbcTemplate.queryForObject(
                """
                SELECT COUNT(*)
                FROM information_schema.tables
                WHERE table_schema = 'public'
                  AND table_name IN (
                      'users',
                      'user_profiles',
                      'password_resets',
                      'lms_clients'
                  )
                """,
                Integer.class
        );

        assertEquals(4, tableCount);
    }

}

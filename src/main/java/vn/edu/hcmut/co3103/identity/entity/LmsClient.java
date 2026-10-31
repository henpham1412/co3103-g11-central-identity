package vn.edu.hcmut.co3103.identity.entity;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Getter;
import lombok.NoArgsConstructor;
import lombok.Setter;
import org.hibernate.annotations.CreationTimestamp;
import org.hibernate.annotations.JdbcTypeCode;
import org.hibernate.type.SqlTypes;

import java.time.Instant;
import java.util.List;

@Entity
@Table(name = "lms_clients")
@Getter
@Setter
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class LmsClient {

    @Id
    @Column(name = "client_id", length = 100, nullable = false)
    private String clientId;

    @Column(name = "client_secret_hash", columnDefinition = "TEXT")
    private String clientSecretHash;

    @Column(name = "client_name", length = 200, nullable = false)
    private String clientName;

    @JdbcTypeCode(SqlTypes.ARRAY)
    @Column(name = "redirect_uris", nullable = false, columnDefinition = "TEXT[]")
    private List<String> redirectUris;

    @Column(name = "is_active", nullable = false)
    @Builder.Default
    private Boolean isActive = true;

    @CreationTimestamp
    @Column(name = "created_at", nullable = false, updatable = false)
    private Instant createdAt;
}

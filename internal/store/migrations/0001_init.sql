CREATE TABLE IF NOT EXISTS threats (
    md5         varchar(32)  PRIMARY KEY,
    name        varchar(200) NOT NULL,
    threat_type varchar(32)  NOT NULL DEFAULT 'other',
    severity    varchar(16)  NOT NULL DEFAULT 'medium',
    status      varchar(24)  NOT NULL DEFAULT 'active',
    description text         NOT NULL DEFAULT '',
    file_type   varchar(255) NOT NULL DEFAULT '',
    file_size   bigint       NOT NULL DEFAULT 0,
    confidence  smallint,
    tags        text[]       NOT NULL DEFAULT '{}',
    source      varchar(64)  NOT NULL DEFAULT 'manual',
    first_seen  timestamptz,
    last_seen   timestamptz,
    created_at  timestamptz  NOT NULL,
    updated_at  timestamptz  NOT NULL,

    CONSTRAINT threats_md5_format CHECK (md5 ~ '^[0-9a-f]{32}$'),
    CONSTRAINT threats_name_not_blank CHECK (btrim(name) <> ''),
    CONSTRAINT threats_threat_type_valid CHECK (threat_type IN (
        'trojan', 'virus', 'worm', 'ransomware', 'spyware', 'adware',
        'rootkit', 'backdoor', 'miner', 'pua', 'other'
    )),
    CONSTRAINT threats_severity_valid CHECK (severity IN ('low', 'medium', 'high', 'critical')),
    CONSTRAINT threats_status_valid CHECK (status IN ('active', 'inactive', 'false_positive', 'under_review')),
    CONSTRAINT threats_file_size_non_negative CHECK (file_size >= 0),
    CONSTRAINT threats_confidence_range CHECK (confidence IS NULL OR confidence BETWEEN 0 AND 100),
    CONSTRAINT threats_tags_limit CHECK (cardinality(tags) <= 20),
    CONSTRAINT threats_seen_order CHECK (
        first_seen IS NULL OR last_seen IS NULL OR last_seen >= first_seen
    )
);

CREATE INDEX IF NOT EXISTS threats_severity_idx ON threats (severity);
CREATE INDEX IF NOT EXISTS threats_updated_at_idx ON threats (updated_at DESC);

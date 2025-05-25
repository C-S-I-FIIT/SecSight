WITH total_rules AS (
    SELECT COUNT(*) AS total_rule_count FROM sigma_rule
),
review_coverage AS (
    SELECT 
        hcr.id AS review_id,
        hcr.host_id,
        h.hostname AS host_name,
        hcr.created_at,
        COUNT(hsc.sigma_id)::float AS covered_count
    FROM host_config_review hcr
    JOIN host h ON h.id = hcr.host_id
    LEFT JOIN host_sigma_compliance hsc 
        ON hsc.host_config_review_id = hcr.id
    GROUP BY hcr.id, hcr.host_id, h.hostname, hcr.created_at
),
coverage_pct_time_series AS (
    SELECT 
        rc.review_id,
        rc.host_id,
        rc.host_name,
        rc.created_at,
        (rc.covered_count / tr.total_rule_count) * 100 AS coverage_pct
    FROM review_coverage rc
    CROSS JOIN total_rules tr
)
SELECT * FROM coverage_pct_time_series;
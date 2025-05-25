-- Sigma Rule Coverage Timeline
-- For a line chart with hosts as lines, time on X-axis, and coverage percentage (0-100%) on Y-axis

WITH total_rules AS (
    SELECT COUNT(*) AS total_count 
    FROM sigma_rule
    WHERE deleted = FALSE
),
host_reviews AS (
    SELECT 
        h.id AS host_id,
        h.hostname,
        hcr.id AS review_id,
        hcr.created_at,
        COUNT(DISTINCT hsc.sigma_id) AS covered_rules_count
    FROM 
        host h
    JOIN 
        host_config_review hcr ON h.id = hcr.host_id
    LEFT JOIN 
        host_sigma_compliance hsc ON hcr.id = hsc.host_config_review_id AND h.id = hsc.host_id
    GROUP BY 
        h.id, h.hostname, hcr.id, hcr.created_at
)
SELECT 
    hr.hostname,
    hr.created_at AS review_date,
    hr.covered_rules_count,
    tr.total_count AS total_rules_count,
    ROUND((hr.covered_rules_count::FLOAT / tr.total_count) * 100, 2) AS coverage_percentage
FROM 
    host_reviews hr
CROSS JOIN 
    total_rules tr
ORDER BY 
    hr.hostname, 
    hr.created_at;

-- Note: This query returns data suitable for a line chart where:
-- - Each line represents a host
-- - X-axis shows the review dates
-- - Y-axis shows the coverage percentage (0-100%)
-- Visualization tools can use hostname as the series identifier 
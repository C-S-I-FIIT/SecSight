-- Sigma Rule Coverage per host with percentage of coverage
WITH total_rules AS (
    SELECT COUNT(*) AS total_count 
    FROM sigma_rule
    WHERE deleted = FALSE
),
host_coverage AS (
    SELECT 
        h.id AS host_id,
        h.hostname,
        h.ip_address,
        COUNT(DISTINCT hsc.sigma_id) AS covered_rules_count
    FROM 
        host h
    LEFT JOIN 
        host_config_review hcr ON h.latest_host_config_review_id = hcr.id
    LEFT JOIN 
        host_sigma_compliance hsc ON hcr.id = hsc.host_config_review_id AND h.id = hsc.host_id
    GROUP BY 
        h.id, h.hostname, h.ip_address
)
SELECT 
    hc.hostname,
    hc.ip_address,
    hc.covered_rules_count,
    tr.total_count AS total_rules_count,
    ROUND((hc.covered_rules_count::FLOAT / tr.total_count) * 100, 2) AS coverage_percentage
FROM 
    host_coverage hc
CROSS JOIN 
    total_rules tr
ORDER BY 
    coverage_percentage DESC; 
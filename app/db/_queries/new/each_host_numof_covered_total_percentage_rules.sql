WITH 
total_rules AS (
    SELECT COUNT(*) AS total_sigma_rules FROM sigma_rule
),
host_coverage AS (
    SELECT 
        h.id AS host_id,
        h.hostname,
        h.ip_address,
        COUNT(DISTINCT hsc.sigma_id) AS covered_rules
    FROM 
        host h
    LEFT JOIN 
        host_sigma_compliance hsc ON h.id = hsc.host_id
    LEFT JOIN 
        host_config_review hcr ON hsc.host_config_review_id = hcr.id
    WHERE 
        hcr.completed = true
        OR hcr.id = h.latest_host_config_review_id
    GROUP BY 
        h.id, h.hostname, h.ip_address
)
SELECT 
    hc.host_id,
    hc.hostname,
    hc.ip_address,
    hc.covered_rules,
    tr.total_sigma_rules,
    (hc.covered_rules * 100.0 / NULLIF(tr.total_sigma_rules, 0))::numeric(10,2) AS coverage_percentage
FROM 
    host_coverage hc
CROSS JOIN 
    total_rules tr
ORDER BY 
    coverage_percentage DESC;
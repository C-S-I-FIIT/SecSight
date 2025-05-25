WITH sigma_rules AS (
    SELECT id, rule_id, name 
    FROM sigma_rule
),
host_compliance AS (
    SELECT 
        h.id AS host_id,
        h.hostname,
        hsc.sigma_id,
        1 AS is_compliant
    FROM 
        host h
    JOIN 
        host_config_review hcr ON h.latest_host_config_review_id = hcr.id
    JOIN 
        host_sigma_compliance hsc ON hsc.host_config_review_id = hcr.id AND hsc.host_id = h.id
    WHERE 
        hcr.completed = true
),
all_hosts AS (
    SELECT id, hostname FROM host
)

SELECT 
    h.hostname,
    sr.id AS rule_id,
    sr.rule_id AS sigma_rule_id,
    sr.name AS rule_name,
    CASE 
        WHEN hc.is_compliant IS NOT NULL THEN 1
        ELSE 0
    END AS is_compliant
FROM 
    all_hosts h
CROSS JOIN 
    sigma_rules sr
LEFT JOIN 
    host_compliance hc ON h.id = hc.host_id AND sr.id = hc.sigma_id
ORDER BY 
    h.hostname, sr.id; 
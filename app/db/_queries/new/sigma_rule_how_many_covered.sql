WITH total_hosts AS (
    SELECT COUNT(*) AS count FROM host
)
SELECT 
    sr.id AS rule_id,
    sr.name AS rule_name,
    sr.rule_id AS sigma_rule_id,
    sr.level AS severity,
    COUNT(DISTINCT hsc.host_id) AS covered_hosts,
    (SELECT count FROM total_hosts) AS total_hosts
FROM 
    sigma_rule sr
LEFT JOIN 
    host_sigma_compliance hsc ON sr.id = hsc.sigma_id
LEFT JOIN 
    host_config_review hcr ON hsc.host_config_review_id = hcr.id
WHERE 
    hcr.completed = true 
    OR hcr.id IN (SELECT latest_host_config_review_id FROM host WHERE latest_host_config_review_id IS NOT NULL)
GROUP BY 
    sr.id, sr.name, sr.rule_id, sr.level, total_hosts
ORDER BY 
    covered_hosts DESC;
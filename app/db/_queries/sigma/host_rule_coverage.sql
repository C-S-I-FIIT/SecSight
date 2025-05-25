-- Sigma rule coverage per host (number of covered rules)
SELECT 
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
ORDER BY 
    covered_rules_count DESC; 
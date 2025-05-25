SELECT
    h.hostname,
    h.ip_address,
    COUNT(DISTINCT sr.id) AS missing_critical_rules,
    STRING_AGG(sr.name, ', ') AS critical_rules_missing
FROM
    host h
CROSS JOIN
    sigma_rule sr
LEFT JOIN
    host_config_review hcr ON h.latest_host_config_review_id = hcr.id
LEFT JOIN
    host_sigma_compliance hsc ON hcr.id = hsc.host_config_review_id AND sr.id = hsc.sigma_id
WHERE
    sr.level IN ('critical', 'high')
    AND sr.enabled = true
    AND sr.deleted = false
    AND hsc.id IS NULL
GROUP BY
    h.id, h.hostname, h.ip_address
HAVING
    COUNT(DISTINCT sr.id) > 0
ORDER BY
    missing_critical_rules DESC
LIMIT 10;
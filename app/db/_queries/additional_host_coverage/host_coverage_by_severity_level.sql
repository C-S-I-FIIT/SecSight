SELECT
    h.hostname,
    h.site,
    sr.level,
    COUNT(DISTINCT hsc.sigma_id) AS covered_rules_count,
    (SELECT COUNT(*) FROM sigma_rule WHERE level = sr.level AND enabled = true AND deleted = false) AS total_rules_by_level,
    (COUNT(DISTINCT hsc.sigma_id) * 100.0 /
        NULLIF((SELECT COUNT(*) FROM sigma_rule WHERE level = sr.level AND enabled = true AND deleted = false), 0)) AS coverage_percentage
FROM
    host h
JOIN
    host_config_review hcr ON h.latest_host_config_review_id = hcr.id
JOIN
    host_sigma_compliance hsc ON hcr.id = hsc.host_config_review_id
JOIN
    sigma_rule sr ON hsc.sigma_id = sr.id
GROUP BY
    h.hostname, h.site, sr.level
ORDER BY
    h.hostname, sr.level;
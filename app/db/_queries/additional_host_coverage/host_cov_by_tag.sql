SELECT
    nt.name AS tag_name,
    COUNT(DISTINCT h.id) AS hosts_count,
    AVG(
        (COUNT(DISTINCT hsc.sigma_id) * 100.0 /
        (SELECT COUNT(*) FROM sigma_rule WHERE enabled = true AND deleted = false))
    ) OVER (PARTITION BY nt.id) AS avg_coverage_percentage
FROM
    netbox_tag nt
JOIN
    tag_device_rule tdr ON nt.id = tdr.tag_id
JOIN
    host h ON tdr.device_id = h.id
LEFT JOIN
    host_config_review hcr ON h.latest_host_config_review_id = hcr.id
LEFT JOIN
    host_sigma_compliance hsc ON hcr.id = hsc.host_config_review_id
GROUP BY
    nt.id, nt.name, h.id
ORDER BY
    avg_coverage_percentage DESC;
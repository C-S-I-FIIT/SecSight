SELECT
    h.platform_os,
    COUNT(DISTINCT h.id) AS host_count,
    AVG(subquery.coverage_percentage) AS avg_coverage_percentage,
    MIN(subquery.coverage_percentage) AS min_coverage_percentage,
    MAX(subquery.coverage_percentage) AS max_coverage_percentage,
    STDDEV(subquery.coverage_percentage) AS stddev_coverage_percentage
FROM
    host h
JOIN (
    SELECT
        h.id,
        (COUNT(DISTINCT hsc.sigma_id) * 100.0 /
            (SELECT COUNT(*) FROM sigma_rule WHERE enabled = true AND deleted = false)) AS coverage_percentage
    FROM
        host h
    LEFT JOIN
        host_config_review hcr ON h.latest_host_config_review_id = hcr.id
    LEFT JOIN
        host_sigma_compliance hsc ON hcr.id = hsc.host_config_review_id
    GROUP BY
        h.id
) AS subquery ON h.id = subquery.id
WHERE
    h.platform_os IS NOT NULL
GROUP BY
    h.platform_os
ORDER BY
    avg_coverage_percentage DESC;
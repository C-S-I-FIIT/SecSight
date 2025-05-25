WITH host_coverage AS (
    SELECT
        h.id,
        h.hostname,
        h.site,
        h.platform_os,
        COUNT(DISTINCT hsc.sigma_id) AS covered_rules
    FROM
        host h
    LEFT JOIN
        host_config_review hcr ON h.latest_host_config_review_id = hcr.id
    LEFT JOIN
        host_sigma_compliance hsc ON hcr.id = hsc.host_config_review_id
    GROUP BY
        h.id, h.hostname, h.site, h.platform_os
),
site_stats AS (
    SELECT
        site,
        AVG(covered_rules) AS avg_coverage,
        STDDEV(covered_rules) AS stddev_coverage
    FROM
        host_coverage
    WHERE
        site IS NOT NULL
    GROUP BY
        site
)
SELECT
    hc.hostname,
    hc.site,
    hc.platform_os,
    hc.covered_rules,
    ss.avg_coverage,
    ss.stddev_coverage,
    (hc.covered_rules - ss.avg_coverage) / NULLIF(ss.stddev_coverage, 0) AS z_score,
    CASE
        WHEN (hc.covered_rules - ss.avg_coverage) / NULLIF(ss.stddev_coverage, 0) < -1 THEN 'Severely Below Average'
        WHEN (hc.covered_rules - ss.avg_coverage) / NULLIF(ss.stddev_coverage, 0) < - 0.3 THEN 'Below Average'
        WHEN (hc.covered_rules - ss.avg_coverage) / NULLIF(ss.stddev_coverage, 0) > 1 THEN 'Exceptionally Above Average'
        WHEN (hc.covered_rules - ss.avg_coverage) / NULLIF(ss.stddev_coverage, 0) > 0.3 THEN 'Above Average'
        ELSE 'Average'
    END AS performance_category
FROM
    host_coverage hc
JOIN
    site_stats ss ON hc.site = ss.site
WHERE
    ss.stddev_coverage > 0
ORDER BY
    ABS((hc.covered_rules - ss.avg_coverage) / NULLIF(ss.stddev_coverage, 0)) DESC;
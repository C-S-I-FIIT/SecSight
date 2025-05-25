-- Area Chart showing MIN, MAX, AVG coverage per MITRE TACTIC
-- Data for area chart showing the range of coverage across hosts for each MITRE tactic

WITH host_count AS (
    SELECT COUNT(DISTINCT id) AS total_hosts
    FROM host
),
tactic_stats AS (
    SELECT
        mt.name AS tactic_name,
        mt.tactic_id,
        h.id AS host_id,
        h.hostname,
        COUNT(DISTINCT sr.id) AS rules_covered,
        COUNT(DISTINCT sr_all.id) AS total_tactic_rules
    FROM
        mitre_tactic mt
    LEFT JOIN
        mitre_tactic_sigma_rule mtsr ON mt.id = mtsr.tactic_id
    LEFT JOIN
        sigma_rule sr_all ON mtsr.sigma_rule_id = sr_all.id AND sr_all.deleted = FALSE
    CROSS JOIN
        host h
    LEFT JOIN
        host_config_review hcr ON h.latest_host_config_review_id = hcr.id
    LEFT JOIN
        host_sigma_compliance hsc ON hcr.id = hsc.host_config_review_id AND h.id = hsc.host_id
    LEFT JOIN
        sigma_rule sr ON hsc.sigma_id = sr.id AND sr.id = sr_all.id
    GROUP BY
        mt.id, mt.name, mt.tactic_id, h.id, h.hostname
    HAVING
        COUNT(DISTINCT sr_all.id) > 0
)
SELECT
    tactic_name,
    tactic_id,
    MIN(ROUND((rules_covered / NULLIF(total_tactic_rules, 0)) * 100, 2)) AS min_coverage_pct,
    MAX(ROUND((rules_covered / NULLIF(total_tactic_rules, 0)) * 100, 2)) AS max_coverage_pct,
    AVG(ROUND((rules_covered / NULLIF(total_tactic_rules, 0)) * 100, 2)) AS avg_coverage_pct,
    ROUND(STDDEV((rules_covered / NULLIF(total_tactic_rules, 0)) * 100),2) AS stddev_coverage_pct,
    COUNT(DISTINCT host_id) AS host_count,
    (SELECT total_hosts FROM host_count) AS total_hosts
FROM
    tactic_stats
GROUP BY
    tactic_name, tactic_id
ORDER BY
    avg_coverage_pct DESC;

-- Note: This query provides data suitable for an area chart where:
-- - X-axis represents different MITRE tactics
-- - Y-axis shows percentage coverage
-- - The area between MIN and MAX shows the range of coverage across hosts
-- - The AVG line shows the average coverage 
-- - STDDEV shows the standard deviation of coverage percentages 
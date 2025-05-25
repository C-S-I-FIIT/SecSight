WITH host_count AS (
    SELECT COUNT(*) AS total_hosts
    FROM host
    WHERE latest_host_config_review_id IS NOT NULL
),
coverage_data AS (
    SELECT
        mt.tactic_id,
        tech.technique_id,
        sub.subtechnique_id,
        COUNT(DISTINCT hsc.host_id) AS covered_hosts,
        (SELECT total_hosts FROM host_count) - COUNT(DISTINCT hsc.host_id) AS uncovered_hosts,
        (SELECT total_hosts FROM host_count) AS total_hosts,
        CASE 
            WHEN (SELECT total_hosts FROM host_count) = 0 THEN 0
        ELSE (COUNT(DISTINCT hsc.host_id) * 100.0 / (SELECT total_hosts FROM host_count))
        END AS coverage_percentage,
        COUNT(DISTINCT sr.id) AS rule_count
    FROM
        mitre_tactic mt
    JOIN
        mitre_tactic_sigma_rule mtsr ON mt.id = mtsr.tactic_id
    JOIN
        sigma_rule sr ON mtsr.sigma_rule_id = sr.id
    JOIN
        mitre_technique_sigma_rule mtesr ON sr.id = mtesr.sigma_rule_id
    JOIN
        mitre_technique tech ON mtesr.technique_id = tech.id
    LEFT JOIN
        mitre_subtechnique_sigma_rule mstsr ON sr.id = mstsr.sigma_rule_id
    LEFT JOIN
        mitre_subtechnique sub ON mstsr.subtechnique_id = sub.id
    LEFT JOIN
        host_sigma_compliance hsc ON sr.id = hsc.sigma_id
    WHERE
        sr.enabled = true
        AND sr.deleted = false
    GROUP BY
        mt.tactic_id, tech.technique_id, sub.subtechnique_id
)
SELECT
    tactic_id,
    technique_id,
    subtechnique_id,
    covered_hosts,
    uncovered_hosts,
    total_hosts,
    ROUND(coverage_percentage, 2) AS coverage_percentage,
    rule_count
FROM
    coverage_data
ORDER BY
    tactic_id, technique_id, subtechnique_id;
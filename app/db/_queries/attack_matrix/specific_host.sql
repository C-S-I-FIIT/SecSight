WITH coverage_data AS (
    SELECT
        mt.tactic_id,
        tech.technique_id,
        sub.subtechnique_id,
        CASE WHEN hsc.id IS NOT NULL THEN 100 ELSE 0 END AS is_covered,
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
        host_sigma_compliance hsc ON sr.id = hsc.sigma_id AND hsc.host_id = {{ host_id }}
    WHERE
        sr.enabled = true
        AND sr.deleted = false
    GROUP BY
        mt.tactic_id, tech.technique_id, sub.subtechnique_id, hsc.id
)
SELECT
    tactic_id,
    technique_id,
    subtechnique_id,
    is_covered,
    rule_count
FROM
    coverage_data
ORDER BY
    tactic_id, technique_id, subtechnique_id;
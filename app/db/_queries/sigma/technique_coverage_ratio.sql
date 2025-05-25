-- Scatter plot - Rule-to-Technique Coverage Ratio
-- Analyzes the balance of rules across MITRE techniques
-- Identifies over-covered and under-covered techniques

WITH technique_coverage AS (
    SELECT
        mt.id AS technique_id,
        mt.technique_id AS technique_code,
        mt.name AS technique_name,
        COUNT(DISTINCT sr.id) AS rule_count
    FROM
        mitre_technique mt
    LEFT JOIN
        mitre_technique_sigma_rule mtsr ON mt.id = mtsr.technique_id
    LEFT JOIN
        sigma_rule sr ON mtsr.sigma_rule_id = sr.id AND sr.deleted = FALSE
    GROUP BY
        mt.id, mt.technique_id, mt.name
)
SELECT
    technique_code,
    technique_name,
    rule_count,
    (SELECT AVG(rule_count) FROM technique_coverage WHERE rule_count > 0) AS avg_rule_count,
    ROUND(rule_count / (SELECT AVG(rule_count) FROM technique_coverage WHERE rule_count > 0), 2) AS coverage_ratio
FROM
    technique_coverage
WHERE
    rule_count > 0  -- Optional: exclude techniques with zero coverage
ORDER BY
    coverage_ratio DESC;


-- Note: This query provides data suitable for a scatter plot where:
-- - X-axis could be the technique name/ID
-- - Y-axis could be the coverage ratio
-- - Points above 1.0 are over-covered compared to average
-- - Points below 1.0 are under-covered compared to average
-- - Size of the point could represent the absolute rule count 
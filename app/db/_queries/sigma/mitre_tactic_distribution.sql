-- Radar Chart showing Sigma rule distribution across Mitre Tactics
-- Data for radar chart where each axis represents a MITRE tactic
-- and the distance from center represents the number of rules for that tactic

SELECT 
    mt.name AS tactic_name,
    mt.tactic_id,
    COUNT(DISTINCT sr.id) AS rule_count,
FROM 
    mitre_tactic mt
LEFT JOIN 
    mitre_tactic_sigma_rule mtsr ON mt.id = mtsr.tactic_id
LEFT JOIN 
    sigma_rule sr ON mtsr.sigma_rule_id = sr.id AND sr.deleted = FALSE
GROUP BY 
    mt.id, mt.name, mt.tactic_id
ORDER BY 
    rule_count DESC;

-- Note: This query provides data points for a radar chart where:
-- - Each axis represents a MITRE tactic
-- - The value on each axis represents the number of sigma rules mapped to that tactic
-- - The shape formed by connecting these points shows the distribution of rules across tactics 
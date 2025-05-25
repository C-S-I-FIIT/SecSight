SELECT
    mt.tactic_id,
    tech.technique_id,
    sub.subtechnique_id,
    100.0 AS coverage_percentage, -- Static 100% coverage
    COUNT(DISTINCT sr.id) AS rule_count
FROM 
    sigma_rule sr
JOIN 
    mitre_tactic_sigma_rule mtsr ON sr.id = mtsr.sigma_rule_id
JOIN 
    mitre_tactic mt ON mtsr.tactic_id = mt.id
JOIN 
    mitre_technique_sigma_rule mtesr ON sr.id = mtesr.sigma_rule_id
JOIN 
    mitre_technique tech ON mtesr.technique_id = tech.id
LEFT JOIN 
    mitre_subtechnique_sigma_rule mstsr ON sr.id = mstsr.sigma_rule_id
LEFT JOIN 
    mitre_subtechnique sub ON mstsr.subtechnique_id = sub.id
WHERE 
    sr.enabled = true 
    AND sr.deleted = false
GROUP BY
    mt.tactic_id, tech.technique_id, sub.subtechnique_id
ORDER BY 
    mt.tactic_id, tech.technique_id, sub.subtechnique_id;
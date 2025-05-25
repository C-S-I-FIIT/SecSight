SELECT 
    mt.tactic_id,
    mt.name as tactic_name,
    COUNT(DISTINCT sr.id) as rule_count
FROM 
    mitre_tactic mt
LEFT JOIN 
    rule_tactics_map rtm ON mt.tactic_id = rtm.tactic_id
LEFT JOIN 
    sigma_rule sr ON rtm.id = sr.id
GROUP BY 
    mt.tactic_id, mt.name
ORDER BY 
    mt.tactic_id; 
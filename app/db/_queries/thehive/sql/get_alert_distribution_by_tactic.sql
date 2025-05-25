SELECT 
    mitre_tactic.name AS tactic_name,
    COUNT(DISTINCT thehive_alert.id) AS count
FROM 
    thehive_alert
JOIN 
    thehive_alert_artifact_map ON thehive_alert.id = thehive_alert_artifact_map.alert_id
JOIN 
    thehive_artifact ON thehive_alert_artifact_map.artifact_id = thehive_artifact.id
JOIN 
    sigma_rule ON thehive_artifact.data = sigma_rule.rule_kibana_id
JOIN 
    mitre_tactic_sigma_rule ON sigma_rule.id = mitre_tactic_sigma_rule.sigma_rule_id
JOIN 
    mitre_tactic ON mitre_tactic_sigma_rule.tactic_id = mitre_tactic.id
WHERE 
    thehive_artifact.data_type = 'kibana-rule-id'
GROUP BY 
    mitre_tactic.name
ORDER BY 
    COUNT(DISTINCT thehive_alert.id) DESC; 
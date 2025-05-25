SELECT 
    sigma_rule.name AS rule_name,
    COUNT(thehive_alert.id) AS count
FROM 
    thehive_alert
JOIN 
    thehive_alert_artifact_map ON thehive_alert.id = thehive_alert_artifact_map.alert_id
JOIN 
    thehive_artifact ON thehive_alert_artifact_map.artifact_id = thehive_artifact.id
JOIN 
    sigma_rule ON thehive_artifact.data = sigma_rule.rule_kibana_id
WHERE 
    thehive_artifact.data_type = 'kibana-rule-id'
GROUP BY 
    sigma_rule.name
ORDER BY 
    COUNT(thehive_alert.id) DESC; 
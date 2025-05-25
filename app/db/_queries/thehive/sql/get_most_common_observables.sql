SELECT 
    thehive_artifact.data_type,
    thehive_artifact.data,
    COUNT(DISTINCT thehive_alert.id) AS count
FROM 
    thehive_artifact
JOIN 
    thehive_alert_artifact_map ON thehive_artifact.id = thehive_alert_artifact_map.artifact_id
JOIN 
    thehive_alert ON thehive_alert_artifact_map.alert_id = thehive_alert.id
GROUP BY 
    thehive_artifact.data_type,
    thehive_artifact.data
ORDER BY 
    COUNT(DISTINCT thehive_alert.id) DESC; 
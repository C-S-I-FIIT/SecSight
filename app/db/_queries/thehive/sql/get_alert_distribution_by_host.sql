SELECT 
    host.hostname,
    COUNT(DISTINCT thehive_alert.id) AS alert_count
FROM 
    host
JOIN 
    thehive_artifact ON split_part(host.ip_address, '/', 1) = thehive_artifact.data
JOIN 
    thehive_alert_artifact_map ON thehive_artifact.id = thehive_alert_artifact_map.artifact_id
JOIN 
    thehive_alert ON thehive_alert_artifact_map.alert_id = thehive_alert.id
WHERE 
    thehive_artifact.data_type = 'ip'
GROUP BY 
    host.hostname
ORDER BY 
    COUNT(DISTINCT thehive_alert.id) DESC; 
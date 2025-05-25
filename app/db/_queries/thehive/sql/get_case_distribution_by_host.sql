SELECT 
    host.hostname,
    COUNT(DISTINCT thehive_case.id) AS case_count
FROM 
    host
JOIN 
    thehive_artifact ON split_part(host.ip_address, '/', 1) = thehive_artifact.data
JOIN 
    thehive_alert_artifact_map ON thehive_artifact.id = thehive_alert_artifact_map.artifact_id
JOIN 
    thehive_alert ON thehive_alert_artifact_map.alert_id = thehive_alert.id
JOIN 
    thehive_case ON thehive_alert.case_id = thehive_case.id
WHERE 
    thehive_artifact.data_type = 'ip'
    AND thehive_alert.case_id IS NOT NULL
GROUP BY 
    host.hostname
ORDER BY 
    COUNT(DISTINCT thehive_case.id) DESC; 
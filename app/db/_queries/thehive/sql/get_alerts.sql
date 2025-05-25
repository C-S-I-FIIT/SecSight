SELECT 
    thehive_alert.id,
    thehive_alert.title,
    thehive_alert.description,
    thehive_alert.severity,
    thehive_alert.date,
    thehive_alert.source,
    thehive_alert.status
FROM 
    thehive_alert
ORDER BY 
    thehive_alert.date DESC; 
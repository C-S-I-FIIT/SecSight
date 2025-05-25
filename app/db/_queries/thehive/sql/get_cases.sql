SELECT 
    thehive_case.id,
    thehive_case.title,
    thehive_case.description,
    thehive_case.severity,
    thehive_case.start_date,
    thehive_case.end_date,
    thehive_case.owner,
    thehive_case.status,
    thehive_case.resolution_status
FROM 
    thehive_case
ORDER BY 
    thehive_case.start_date DESC; 
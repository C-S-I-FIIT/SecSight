SELECT 
    thehive_case.resolution_status,
    COUNT(thehive_case.id) AS count
FROM 
    thehive_case
WHERE 
    thehive_case.status = 'Resolved'
GROUP BY 
    thehive_case.resolution_status
ORDER BY 
    COUNT(thehive_case.id) DESC; 
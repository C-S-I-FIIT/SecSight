SELECT 
    thehive_case.status,
    COUNT(thehive_case.id) AS count
FROM 
    thehive_case
GROUP BY 
    thehive_case.status
ORDER BY 
    COUNT(thehive_case.id) DESC; 
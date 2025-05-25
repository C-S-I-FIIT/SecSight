SELECT 
    thehive_case.owner,
    COUNT(thehive_case.id) AS count
FROM 
    thehive_case
GROUP BY 
    thehive_case.owner
ORDER BY 
    COUNT(thehive_case.id) DESC; 
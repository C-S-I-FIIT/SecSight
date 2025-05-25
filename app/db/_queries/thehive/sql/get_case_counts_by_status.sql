-- Map 'Closed' to 'Resolved' for status parameter
WITH status_param AS (
    SELECT 
        CASE 
            WHEN :status = 'Closed' THEN 'Resolved'
            ELSE :status
        END AS mapped_status
)

SELECT 
    COUNT(thehive_case.id) AS count
FROM 
    thehive_case, status_param
WHERE 
    thehive_case.status = status_param.mapped_status; 
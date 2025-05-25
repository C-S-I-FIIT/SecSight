SELECT 
    AVG(
        CASE 
            WHEN thehive_case.end_date IS NOT NULL THEN 
                EXTRACT(EPOCH FROM (thehive_case.end_date - thehive_case.start_date))
            ELSE 
                EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - thehive_case.start_date))
        END
    )::TEXT || ' seconds'::INTERVAL AS avg_resolution_time
FROM 
    thehive_case
WHERE 
    thehive_case.start_date IS NOT NULL; 
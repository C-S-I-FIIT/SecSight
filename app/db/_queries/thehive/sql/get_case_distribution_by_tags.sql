SELECT 
    tag, 
    COUNT(*) AS count
FROM 
    thehive_case,
    jsonb_array_elements_text(tags::jsonb) AS tag
WHERE
    tag NOT IN ('elastalert', 'kibana-alert')
GROUP BY 
    tag
ORDER BY 
    count DESC; 
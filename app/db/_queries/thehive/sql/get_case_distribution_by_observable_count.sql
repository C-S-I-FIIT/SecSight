-- Get the count of observables per case
WITH observable_counts AS (
    SELECT 
        thehive_alert.case_id,
        COUNT(DISTINCT thehive_artifact.id) AS observable_count
    FROM 
        thehive_alert
    JOIN 
        thehive_alert_artifact_map ON thehive_alert.id = thehive_alert_artifact_map.alert_id
    JOIN 
        thehive_artifact ON thehive_alert_artifact_map.artifact_id = thehive_artifact.id
    WHERE 
        thehive_alert.case_id IS NOT NULL
    GROUP BY 
        thehive_alert.case_id
)

-- Main query
SELECT 
    thehive_case.id AS case_id,
    thehive_case.title,
    observable_counts.observable_count
FROM 
    thehive_case
JOIN 
    observable_counts ON thehive_case.id = observable_counts.case_id
ORDER BY 
    observable_counts.observable_count DESC; 
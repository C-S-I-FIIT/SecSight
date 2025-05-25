-- Create a subquery for host artifacts
WITH host_artifacts AS (
    SELECT
        thehive_artifact.id AS artifact_id,
        thehive_artifact.data AS ip_address,
        host.id AS host_id,
        host.hostname
    FROM
        thehive_artifact
    JOIN
        host ON thehive_artifact.data = split_part(host.ip_address, '/', 1)
    WHERE
        thehive_artifact.data_type = 'ip'
        AND split_part(host.ip_address, '/', 1) = :host_ip
)

-- Main query to get alerts
SELECT DISTINCT
    thehive_alert.id AS alert_id,
    thehive_alert.title,
    thehive_alert.description,
    thehive_alert.severity,
    thehive_alert.date,
    thehive_alert.source,
    thehive_alert.status,
    host_artifacts.hostname,
    host_artifacts.ip_address
FROM
    thehive_alert
JOIN 
    thehive_alert_artifact_map ON thehive_alert.id = thehive_alert_artifact_map.alert_id
JOIN
    thehive_artifact ON thehive_alert_artifact_map.artifact_id = thehive_artifact.id
JOIN
    host_artifacts ON thehive_artifact.id = host_artifacts.artifact_id
ORDER BY
    thehive_alert.date DESC; 
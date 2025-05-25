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
),
-- Create a subquery for host alerts
host_alerts AS (
    SELECT DISTINCT
        thehive_alert.id AS alert_id,
        thehive_alert.case_id,
        host_artifacts.hostname,
        host_artifacts.ip_address
    FROM
        thehive_alert
    JOIN
        thehive_alert_artifact_map ON thehive_alert.id = thehive_alert_artifact_map.alert_id
    JOIN
        host_artifacts ON thehive_alert_artifact_map.artifact_id = host_artifacts.artifact_id
    WHERE
        thehive_alert.case_id IS NOT NULL
),
-- Create a subquery for sigma rule mappings
sigma_mappings AS (
    SELECT
        thehive_alert.id AS alert_id,
        thehive_alert.case_id,
        sigma_rule.id AS sigma_id,
        sigma_rule.rule_id,
        sigma_rule.name AS sigma_name,
        sigma_rule.description AS sigma_description,
        sigma_rule.severity AS sigma_severity
    FROM
        thehive_alert
    JOIN
        thehive_alert_artifact_map ON thehive_alert.id = thehive_alert_artifact_map.alert_id
    JOIN
        thehive_artifact ON thehive_alert_artifact_map.artifact_id = thehive_artifact.id
    JOIN
        sigma_rule ON thehive_artifact.data = sigma_rule.rule_id
    WHERE
        thehive_artifact.data_type = 'kibana-rule-id'
        AND thehive_alert.case_id IS NOT NULL
)
-- Main query to get cases with sigma rules
SELECT DISTINCT
    thehive_case.id AS case_id,
    thehive_case.hive_id,
    thehive_case.title AS case_title,
    thehive_case.description AS case_description,
    thehive_case.severity AS case_severity,
    thehive_case.start_date,
    thehive_case.end_date,
    thehive_case.status AS case_status,
    thehive_case.resolution_status,
    host_alerts.hostname,
    host_alerts.ip_address,
    sigma_mappings.sigma_id,
    sigma_mappings.rule_id AS sigma_rule_id,
    sigma_mappings.sigma_name,
    sigma_mappings.sigma_severity
FROM
    thehive_case
JOIN
    host_alerts ON thehive_case.id = host_alerts.case_id
LEFT JOIN
    sigma_mappings ON thehive_case.id = sigma_mappings.case_id
ORDER BY
    thehive_case.start_date DESC; 
WITH compliant_rules AS (
    SELECT DISTINCT sigma_id
    FROM host_sigma_compliance hsc
    WHERE hsc.host_id = 1  -- Replace with your host ID
    AND hsc.host_config_review_id = (
        SELECT latest_host_config_review_id 
        FROM host 
        WHERE id = 1  -- Replace with your host ID
    )
),
base_data AS (
    SELECT
        sr.id as sigma_rule_id,
        sr.name as sigma_name, 
        CASE
            WHEN sr.log_source_category IS NOT NULL AND sr.log_source_category != '' THEN sr.log_source_category
            WHEN sr.log_source_service IS NOT NULL AND sr.log_source_service != '' THEN sr.log_source_service
            ELSE NULL
        END AS sigma_log_source,
        sr.log_source_product,
        sr.level as sigma_level,
        swls.windows_event_channel,
        swls.event_id as windows_event_id
    FROM sigma_rule sr
    LEFT JOIN sigma_rule_windows_log_map srwm ON sr.id = srwm.sigma_rule_id
    LEFT JOIN sigma_windows_log_source swls ON srwm.windows_log_source_id = swls.id
    WHERE sr.id NOT IN (SELECT sigma_id FROM compliant_rules)
    AND sr.deleted = false
    AND sr.enabled = true
),
ranked_data AS (
    SELECT *,
           ROW_NUMBER() OVER (
               PARTITION BY sigma_rule_id, sigma_log_source
               ORDER BY 
                   CASE WHEN windows_event_id IS NOT NULL THEN 0 ELSE 1 END,
                   windows_event_id -- Optional: if multiple event_ids, prefer lower
           ) AS rn
    FROM base_data
)
SELECT 
    sigma_rule_id,
    sigma_name,
    sigma_log_source,
    log_source_product,
    sigma_level,
    windows_event_channel,
    windows_event_id
FROM ranked_data
WHERE rn = 1;
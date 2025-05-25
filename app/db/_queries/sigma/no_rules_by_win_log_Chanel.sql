SELECT
    swls.windows_event_channel,
    CASE WHEN sr.log_source_category = '' THEN sr.log_source_service ELSE sr.log_source_category END AS sigma_log_source,
    COUNT(DISTINCT sr.id) AS rule_count
FROM
    sigma_rule sr
JOIN
    sigma_rule_windows_log_map srlm ON sr.id = srlm.sigma_rule_id
JOIN
    sigma_windows_log_source swls ON srlm.windows_log_source_id = swls.id
WHERE
    sr.deleted = FALSE OR sr.deleted IS NULL
GROUP BY
    swls.windows_event_channel, sr.log_source_category, sr.log_source_service
ORDER BY
    COUNT(DISTINCT sr.id) DESC,
    swls.windows_event_channel,
    sr.log_source_category,
    sr.log_source_service;
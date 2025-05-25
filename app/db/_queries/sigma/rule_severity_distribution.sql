-- Bar chart showing distribution of Rule severities for all Rules
-- Data for a simple bar chart showing the count of rules per severity level

SELECT 
    COALESCE(severity, 'undefined') AS severity_level,
    COUNT(*) AS rule_count
FROM 
    sigma_rule
WHERE 
    deleted = FALSE
GROUP BY 
    severity_level
ORDER BY 
    CASE 
        WHEN severity_level = 'critical' THEN 1
        WHEN severity_level = 'high' THEN 2
        WHEN severity_level = 'medium' THEN 3
        WHEN severity_level = 'low' THEN 4
        ELSE 5
    END;

-- Note: This query provides data suitable for a bar chart where:
-- - X-axis represents different severity levels (critical, high, medium, low, undefined)
-- - Y-axis shows the count of rules for each severity level 
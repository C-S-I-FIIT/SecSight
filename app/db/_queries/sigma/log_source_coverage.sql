-- Log Source Category Coverage Analysis - As Treemap
-- Purpose: Analyzes rule coverage by log source category, service, and product
-- Shows which log sources have the most comprehensive monitoring

WITH log_source_rules AS (
    SELECT 
        COALESCE(sr.log_source_category, 'Unknown') AS category,
        COALESCE(sr.log_source_service, 'Unknown') AS service,
        COALESCE(sr.log_source_product, 'Unknown') AS product,
        COUNT(DISTINCT sr.id) AS total_rules,
        SUM(CASE WHEN sr.enabled THEN 1 ELSE 0 END) AS enabled_rules
    FROM 
        sigma_rule sr
    WHERE 
        sr.deleted = FALSE
    GROUP BY 
        category, service, product
)
SELECT 
    category,
    service, 
    product,
    total_rules,
    enabled_rules,
    ROUND((enabled_rules::FLOAT / NULLIF(total_rules, 0)) * 100, 2) AS enabled_percentage
FROM 
    log_source_rules
ORDER BY 
    total_rules DESC, 
    category, 
    service, 
    product;

-- Note: This query provides data suitable for a treemap where:
-- - The main rectangles represent log source categories
-- - The sub-rectangles represent services within categories
-- - The smallest rectangles represent products within services
-- - The size of each rectangle corresponds to the number of rules
-- - Color intensity could represent the percentage of enabled rules 
WITH total_rules AS (
    SELECT COUNT(DISTINCT id) as total_count
    FROM sigma_rule
),
covered_rules AS (
    SELECT COUNT(DISTINCT hsc.sigma_id) as covered_count
    FROM host_sigma_compliance hsc
    JOIN host_config_review hcr ON hsc.host_config_review_id = hcr.id
    WHERE hcr.completed = true
)
SELECT 
    tr.total_count as total_sigma_rule,
    cr.covered_count as covered_rules,
    ROUND((cr.covered_count::float / tr.total_count::float) * 100, 2) as coverage_percentage
FROM 
    total_rules tr,
    covered_rules cr; 
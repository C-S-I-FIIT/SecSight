-- Configuration Consistency Analysis - as HeatMap
-- Purpose: Analyzes configuration consistency across sites, identifying areas with inconsistent security monitoring

WITH site_stats AS (
    SELECT 
        h.site,
        sr.rule_id AS sigma_rule_id,
        sr.name AS rule_name,
        COUNT(DISTINCT h.id) AS total_hosts_in_site,
        COUNT(DISTINCT hsc.host_id) AS compliant_hosts_in_site
    FROM 
        host h
    CROSS JOIN 
        sigma_rule sr
    LEFT JOIN 
        host_config_review hcr ON h.latest_host_config_review_id = hcr.id
    LEFT JOIN 
        host_sigma_compliance hsc ON hcr.id = hsc.host_config_review_id 
            AND h.id = hsc.host_id 
            AND hsc.sigma_id = sr.id
    WHERE 
        sr.deleted = FALSE
    GROUP BY 
        h.site, sr.rule_id, sr.name
    HAVING 
        COUNT(DISTINCT h.id) > 0
)
SELECT 
    site,
    sigma_rule_id,
    rule_name,
    total_hosts_in_site,
    compliant_hosts_in_site,
    ROUND((compliant_hosts_in_site::FLOAT / total_hosts_in_site) * 100, 2) AS compliance_percentage
FROM 
    site_stats
ORDER BY 
    site, 
    compliance_percentage DESC;

-- Note: This query provides data suitable for a heatmap where:
-- - Y-axis could show different sites
-- - X-axis could show different rules
-- - Cell color intensity could represent the compliance percentage
-- - This helps identify inconsistently applied monitoring across different sites 
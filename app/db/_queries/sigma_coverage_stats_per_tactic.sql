WITH rule_coverage AS (
    SELECT 
        mt.tactic_id,
        mt.name as tactic_name,
        h.hostname,
        COUNT(DISTINCT CASE WHEN hsc.sigma_id IS NOT NULL THEN sr.id END) as covered_rules,
        COUNT(DISTINCT sr.id) as total_rules,
        ROUND(COALESCE(COUNT(DISTINCT CASE WHEN hsc.sigma_id IS NOT NULL THEN sr.id END) * 100.0 / 
         NULLIF(COUNT(DISTINCT sr.id), 0), 0), 2) as coverage_percentage
    FROM 
        mitre_tactic mt
    LEFT JOIN 
        rule_tactics_map rtm ON mt.tactic_id = rtm.tactic_id
    LEFT JOIN 
        sigma_rule sr ON rtm.id = sr.id
    CROSS JOIN 
        hosts h
    LEFT JOIN 
        host_sigma_compliance hsc ON hsc.sigma_id = sr.id 
        AND hsc.host_id = h.id
        AND hsc.host_config_review_id = h.latest_host_config_review_id
    GROUP BY 
        mt.tactic_id, mt.name, h.hostname
)
SELECT 
    tactic_id,
    tactic_name,
    ROUND(COALESCE(MIN(coverage_percentage), 0), 2) as min_coverage,
    ROUND(COALESCE(AVG(coverage_percentage), 0), 2) as avg_coverage,
    ROUND(COALESCE(MAX(coverage_percentage), 0), 2) as max_coverage
FROM 
    rule_coverage
GROUP BY 
    tactic_id, tactic_name
ORDER BY 
    tactic_id; 
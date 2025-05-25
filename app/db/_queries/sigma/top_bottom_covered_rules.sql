-- Top 10 most covered rules
WITH rule_coverage AS (
    SELECT 
        sr.id AS rule_id,
        sr.name AS rule_name,
        sr.rule_id AS sigma_rule_id,
        COUNT(DISTINCT hsc.host_id) AS compliant_hosts_count
    FROM 
        sigma_rule sr
    LEFT JOIN 
        host_sigma_compliance hsc ON sr.id = hsc.sigma_id
    WHERE 
        sr.deleted = FALSE
    GROUP BY 
        sr.id, sr.name, sr.rule_id
)

-- Top 10 most covered rules
SELECT 
    rule_name,
    sigma_rule_id,
    compliant_hosts_count,
    'Most Covered' AS category
FROM 
    rule_coverage
ORDER BY 
    compliant_hosts_count DESC
LIMIT 10

UNION ALL

-- Top 10 rules with smallest number of compliant hosts
SELECT 
    rule_name,
    sigma_rule_id,
    compliant_hosts_count,
    'Least Covered' AS category
FROM 
    rule_coverage
WHERE 
    compliant_hosts_count > 0  -- Optional: exclude rules with zero coverage
ORDER BY 
    compliant_hosts_count ASC
LIMIT 10

ORDER BY 
    category,
    compliant_hosts_count DESC; 
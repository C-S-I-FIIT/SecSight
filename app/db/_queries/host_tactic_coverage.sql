WITH tactic_rule_counts AS (
    -- Count total number of sigma rules per tactic
    SELECT 
        mt.id AS tactic_id,
        mt.name AS tactic_name,
        COUNT(DISTINCT rtm.sigma_rule_id) AS total_rules
    FROM 
        mitre_tactic mt
    LEFT JOIN 
        mitre_tactic_sigma_rule rtm ON mt.id = rtm.tactic_id
    GROUP BY 
        mt.id, mt.name
),
host_compliant_rules AS (
    -- Get all compliant rules for each host's latest review
    SELECT 
        h.id AS host_id,
        h.hostname,
        hsc.sigma_id
    FROM 
        host h
    JOIN 
        host_config_review hcr ON h.latest_host_config_review_id = hcr.id
    JOIN 
        host_sigma_compliance hsc ON hsc.host_config_review_id = hcr.id AND hsc.host_id = h.id
    WHERE 
        hcr.completed = true
),
host_tactic_rule_coverage AS (
    -- Calculate how many rules per tactic each host complies with
    SELECT 
        hcr.host_id,
        hcr.hostname,
        rtm.tactic_id,
        COUNT(DISTINCT hcr.sigma_id) AS covered_rules
    FROM 
        host_compliant_rules hcr
    JOIN 
        mitre_tactic_sigma_rule rtm ON hcr.sigma_id = rtm.sigma_rule_id
    GROUP BY 
        hcr.host_id, hcr.hostname, rtm.tactic_id
),
all_hosts AS (
    SELECT id, hostname FROM host
)

SELECT 
    h.hostname,
    mt.tactic_id,
    mt.name AS tactic_name,
    trc.total_rules,
    COALESCE(htrc.covered_rules, 0) AS covered_rules,
    CASE 
        WHEN trc.total_rules > 0 THEN 
            (COALESCE(htrc.covered_rules, 0)::float / trc.total_rules::float) * 100
        ELSE 0 
    END AS coverage_percentage
FROM 
    all_hosts h
CROSS JOIN 
    mitre_tactic mt
JOIN 
    tactic_rule_counts trc ON mt.id = trc.tactic_id
LEFT JOIN 
    host_tactic_rule_coverage htrc ON h.id = htrc.host_id AND mt.id = htrc.tactic_id
ORDER BY 
    h.hostname, mt.tactic_id; 
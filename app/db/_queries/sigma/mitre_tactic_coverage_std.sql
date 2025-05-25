-- Radar Chart showing Sigma rule distribution across Mitre Tactics with statistics
-- Data for radar chart where each axis represents a MITRE tactic
-- and values show average coverage and standard deviation across hosts

WITH tactic_rules AS (
    -- Get total number of rules per tactic
    SELECT 
        mt.id AS tactic_id,
        mt.name AS tactic_name,
        mt.tactic_id AS mitre_tactic_id,
        COUNT(DISTINCT sr.id) AS total_rules
    FROM 
        mitre_tactic mt
    LEFT JOIN 
        mitre_tactic_sigma_rule mtsr ON mt.id = mtsr.tactic_id
    LEFT JOIN 
        sigma_rule sr ON mtsr.sigma_rule_id = sr.id AND sr.deleted = FALSE
    GROUP BY 
        mt.id, mt.name, mt.tactic_id
),
host_tactic_data AS (
    -- Get only relevant host-tactic-rule combinations
    SELECT 
        h.id AS host_id,
        mtsr.tactic_id,
        sr.id AS rule_id
    FROM 
        host h
    JOIN 
        host_sigma_compliance hsc ON h.id = hsc.host_id
    JOIN 
        sigma_rule sr ON hsc.sigma_id = sr.id AND sr.deleted = FALSE
    JOIN 
        mitre_tactic_sigma_rule mtsr ON sr.id = mtsr.sigma_rule_id
),
host_tactic_counts AS (
    -- Calculate rules covered per host per tactic
    SELECT 
        host_id,
        tr.tactic_id,
        tr.tactic_name,
        tr.mitre_tactic_id,
        tr.total_rules,
        COUNT(DISTINCT htd.rule_id) AS covered_rules
    FROM 
        tactic_rules tr
    CROSS JOIN (SELECT DISTINCT id FROM host) h
    LEFT JOIN 
        host_tactic_data htd ON tr.tactic_id = htd.tactic_id AND h.id = htd.host_id
    GROUP BY 
        host_id, tr.tactic_id, tr.tactic_name, tr.mitre_tactic_id, tr.total_rules
),
host_tactic_percentages AS (
    -- Calculate percentage of rules covered per host and tactic
    SELECT
        host_id,
        tactic_name,
        mitre_tactic_id,
        CASE 
            WHEN total_rules = 0 THEN 0
            WHEN covered_rules > total_rules THEN 100 -- Cap at 100%
            ELSE (covered_rules * 100.0 / total_rules) 
        END AS coverage_percentage
    FROM
        host_tactic_counts
)
-- Calculate statistics across hosts for each tactic
SELECT 
    tactic_name,
    mitre_tactic_id,
    ROUND(AVG(coverage_percentage)::numeric, 2) AS avg_coverage_percent,
    ROUND(STDDEV(coverage_percentage)::numeric, 2) AS stddev_coverage_percent,
    COUNT(DISTINCT host_id) AS host_count
FROM 
    host_tactic_percentages
GROUP BY 
    tactic_name, mitre_tactic_id
ORDER BY 
    avg_coverage_percent DESC;

-- Note: This query provides data points for a radar chart where:
-- - Each axis represents a MITRE tactic
-- - The main value on each axis is the average coverage percentage across all hosts
-- - The standard deviation shows the variation in coverage between hosts
-- - This helps visualize both overall coverage and consistency across the infrastructure 
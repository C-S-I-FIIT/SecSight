-- Rule coverage by host
WITH all_pairs AS (
    SELECT 
        h.id AS host_id,
        h.hostname,
        s.id AS sigma_id
    FROM host h
    CROSS JOIN sigma_rule s
),
latest_review_matches AS (
    SELECT 
        hsc.host_id,
        hsc.sigma_id
    FROM host_sigma_compliance hsc
    JOIN host h 
        ON h.id = hsc.host_id 
        AND h.latest_host_config_review_id = hsc.host_config_review_id
),
coverage_status AS (
    SELECT 
        ap.host_id,
        ap.hostname,
        ap.sigma_id,
        CASE 
            WHEN lrm.sigma_id IS NOT NULL THEN 'covered'
            ELSE 'missing'
        END AS status
    FROM all_pairs ap
    LEFT JOIN latest_review_matches lrm 
        ON ap.host_id = lrm.host_id 
        AND ap.sigma_id = lrm.sigma_id
)
SELECT 
    host_id,
    hostname,
    COUNT(*) AS total_rules,
    COUNT(*) FILTER (WHERE status = 'covered') AS covered_rules,
    ROUND(COUNT(*) FILTER (WHERE status = 'covered')::float / COUNT(*) * 100, 2) AS coverage_percentage
FROM coverage_status
GROUP BY host_id, hostname;

-- Overall rule coverage statistics
WITH all_pairs AS (
    SELECT 
        h.id AS host_id,
        s.id AS sigma_id
    FROM host h
    CROSS JOIN sigma_rule s
),
latest_review_matches AS (
    SELECT 
        hsc.host_id,
        hsc.sigma_id
    FROM host_sigma_compliance hsc
    JOIN host h 
        ON h.id = hsc.host_id 
        AND h.latest_host_config_review_id = hsc.host_config_review_id
)
SELECT 
    COUNT(DISTINCT sigma_id) AS total_rules,
    COUNT(DISTINCT sigma_id) FILTER (WHERE EXISTS (
        SELECT 1 FROM latest_review_matches lrm 
        WHERE lrm.sigma_id = ap.sigma_id
    )) AS covered_rules
FROM all_pairs ap;

-- Rule coverage by MITRE tactic
WITH all_pairs AS (
    SELECT 
        mt.name AS tactic_name,
        s.id AS sigma_id
    FROM mitre_tactic mt
    JOIN rule_tactics_map rtm ON mt.tactic_id = rtm.tactic_id
    JOIN sigma_rule s ON s.id = rtm.id
),
latest_review_matches AS (
    SELECT DISTINCT
        hsc.sigma_id
    FROM host_sigma_compliance hsc
    JOIN host h 
        ON h.id = hsc.host_id 
        AND h.latest_host_config_review_id = hsc.host_config_review_id
)
SELECT 
    ap.tactic_name,
    COUNT(DISTINCT ap.sigma_id) AS total_rules,
    COUNT(DISTINCT ap.sigma_id) FILTER (WHERE lrm.sigma_id IS NOT NULL) AS covered_rules,
    ROUND(COUNT(DISTINCT ap.sigma_id) FILTER (WHERE lrm.sigma_id IS NOT NULL)::float / 
          COUNT(DISTINCT ap.sigma_id) * 100, 2) AS coverage_percentage
FROM all_pairs ap
LEFT JOIN latest_review_matches lrm ON ap.sigma_id = lrm.sigma_id
GROUP BY ap.tactic_name;

-- Host coverage timeline
WITH timeline_data AS (
    SELECT 
        h.hostname,
        hcr.created_at,
        hsc.sigma_id,
        hsc.host_config_review_id
    FROM host_config_review hcr
    JOIN host h ON h.id = hcr.host_id
    JOIN host_sigma_compliance hsc ON hcr.id = hsc.host_config_review_id
    WHERE h.id = :host_id
)
SELECT 
    hostname,
    created_at,
    COUNT(DISTINCT sigma_id) AS total_rules,
    COUNT(DISTINCT sigma_id) FILTER (WHERE host_config_review_id IS NOT NULL) AS covered_rules,
    ROUND(COUNT(DISTINCT sigma_id) FILTER (WHERE host_config_review_id IS NOT NULL)::float / 
          COUNT(DISTINCT sigma_id) * 100, 2) AS coverage_percentage
FROM timeline_data
GROUP BY hostname, created_at
ORDER BY created_at; 





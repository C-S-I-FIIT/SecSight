WITH host_count AS (
    SELECT COUNT(*) AS total_hosts
    FROM host
    WHERE latest_host_config_review_id IS NOT NULL
),

without_subtech AS (
    
    SELECT DISTINCT 
	sr.id as sigma_id,
	mt.tactic_id AS tactic_id,
	mtech.technique_id AS technique_id,
	NULL AS subtechnique_id

    FROM sigma_rule AS sr
	JOIN
		mitre_technique_sigma_rule AS mtsr ON mtsr.sigma_rule_id = sr.id
	JOIN
		mitre_technique AS mtech ON mtech.id = mtsr.technique_id
	JOIN
		mitre_technique_tactic_map AS mttm ON mttm.technique_id = mtech.id
	JOIN
		mitre_tactic AS mt ON mt.id = mttm.tactic_id
	WHERE 
	sr.enabled = true AND sr.deleted = false
	AND mtech.id NOT IN (

	SELECT  technique_id FROM mitre_subtechnique
	
	)
	ORDER BY 
    mt.tactic_id, mtech.technique_id
),

with_subtech AS (

SELECT DISTINCT
	sr.id as sigma_id,
	mt.tactic_id AS tactic_id,
	mtech.technique_id AS technique_id,
	msub.subtechnique_id AS subtechnique_id
FROM 
    sigma_rule sr
JOIN
	mitre_subtechnique_sigma_rule mssr ON mssr.sigma_rule_id = sr.id
JOIN
	mitre_subtechnique As msub ON msub.id = mssr.subtechnique_id
JOIN
	mitre_technique AS mtech ON msub.technique_id = mtech.id
JOIN
	mitre_technique_tactic_map AS mttm ON mttm.technique_id = mtech.id
JOIN
	mitre_tactic AS mt ON mt.id = mttm.tactic_id
WHERE 
    sr.enabled = true 
    AND sr.deleted = false
ORDER BY 
    mt.tactic_id, mtech.technique_id, msub.subtechnique_id
),

merge_data AS (
SELECT * FROM without_subtech UNION SELECT * FROM with_subtech
)

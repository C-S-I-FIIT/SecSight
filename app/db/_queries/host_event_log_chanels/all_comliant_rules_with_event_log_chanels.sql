WITH latest_compliance_review AS (
    SELECT MAX(host_config_review_id) AS id
    FROM host_sigma_compliance
    WHERE host_id = 7
)
SELECT 
    h.id AS host_id,
    h.hostname,
	h.ip_address,
    -- hcr.id AS config_review_id,
    -- hcr.created_at AS review_date,
    -- hcr.completed AS review_completed,
    sr.rule_id as rule_id,
    sr.name AS rule_name,
    sr.log_source_category,
    sr.log_source_product,
    sr.level,
    -- sr.tags,
    -- sr.description,
    wls.windows_event_channel,
    wls.event_id AS windows_event_id,
    mt.name AS mitre_tactic,
    mt.tactic_id AS mitre_tactic_id,
    mte.name AS mitre_technique,
    mte.technique_id AS mitre_technique_id,
    mst.name AS mitre_subtechnique,
    mst.subtechnique_id AS mitre_subtechnique_id
FROM 
    host h
JOIN 
    host_config_review hcr ON h.id = hcr.host_id
JOIN 
    latest_compliance_review lcr ON hcr.id = lcr.id
JOIN 
    host_sigma_compliance hc ON hcr.id = hc.host_config_review_id AND h.id = hc.host_id
JOIN 
    sigma_rule sr ON hc.sigma_id = sr.id
-- Windows log sources
LEFT JOIN
    sigma_rule_windows_log_map srwlm ON sr.id = srwlm.sigma_rule_id
LEFT JOIN
    sigma_windows_log_source wls ON srwlm.windows_log_source_id = wls.id
-- MITRE tactics
LEFT JOIN
    mitre_tactic_sigma_rule mtsr ON sr.id = mtsr.sigma_rule_id
LEFT JOIN
    mitre_tactic mt ON mtsr.tactic_id = mt.id
-- MITRE techniques
LEFT JOIN
    mitre_technique_sigma_rule mtesr ON sr.id = mtesr.sigma_rule_id
LEFT JOIN
    mitre_technique mte ON mtesr.technique_id = mte.id
-- MITRE subtechniques - using lateral join for proper technique-subtechnique linking
CROSS JOIN LATERAL (
    SELECT 
        mst.id AS id,
        mst.name AS name,
        mst.subtechnique_id AS subtechnique_id
    FROM 
        mitre_subtechnique_sigma_rule mstsr
    JOIN 
        mitre_subtechnique mst ON mstsr.subtechnique_id = mst.id
    WHERE 
        mstsr.sigma_rule_id = sr.id
        AND (mst.technique_id = mte.id OR mte.id IS NULL)
    LIMIT 1
) mst
WHERE 
    h.id = 7
ORDER BY 
    sr.name, mt.name, mte.name, mst.name;
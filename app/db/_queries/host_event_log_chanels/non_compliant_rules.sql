WITH compliant_rules AS (
SELECT 
    h.hostname,
    sr.rule_id AS rule_id,
    sr.name as rule_name,
    sr.description,
    sr.level,
    sr.severity,
    sr.status,
    sr.tags,
    hcr.created_at as review_date
FROM 
    host h
    INNER JOIN host_config_review hcr ON h.latest_host_config_review_id = hcr.id
    JOIN host_sigma_compliance hsc ON hcr.host_id = hsc.host_config_review_id
    JOIN sigma_rule sr ON hsc.sigma_id = sr.id
	WHERE 
		h.id = 1 AND
	    sr.deleted = false 
	    AND sr.enabled = true
	ORDER BY 
	    sr.severity DESC, sr.name
		)

SELECT * FROM sigma_rule sr WHERE sr.rule_id NOT IN (SELECT rule_id FROM compliant_rules) AND enabled = true AND deleted = false;
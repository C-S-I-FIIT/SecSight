from app.db.database import Database

from app.db.models import TheHiveAlert, TheHiveCase, TheHiveArtifact, Host, SigmaRule, HostSigmaCompliance
from app.db.models import alert_artifact_map, MitreTactic, MitreTechnique, rule_tactics_map

from sqlalchemy import select, join, func, and_, or_, case, distinct, text, cast, String, JSON
from sqlalchemy.sql.expression import literal_column

import pandas as pd
import json
import os


class MitreAttackData:
    """Class to handle MITRE ATT&CK data loading and processing"""
    
    _instance = None
    
    @classmethod
    def get_instance(cls):
        """Singleton pattern to ensure data is loaded only once"""
        if cls._instance is None:
            cls._instance = MitreAttackData()
        return cls._instance
    
    def __init__(self):
        """Initialize and load MITRE ATT&CK data from the enterprise-attack.json file"""
        self.tactics = {}
        self.techniques = {}
        self.mitigations = {}
        self.relationships = []
        
        # Load the STIX data
        self._load_data()
    
    def _load_data(self):
        """Load MITRE ATT&CK data from the enterprise-attack.json file"""
        try:
            # Path to the enterprise-attack.json file
            file_path = os.path.join(os.path.dirname(__file__), '..', '..', '..', 'data', 'enterprise-attack.json')
            
            with open(file_path, 'r') as f:
                data = json.load(f)
                
            # Process all objects in the STIX bundle
            for obj in data.get('objects', []):
                obj_type = obj.get('type')
                obj_id = obj.get('id')
                
                # Process tactics (x-mitre-tactic)
                if obj_type == 'x-mitre-tactic':
                    tactic_id = next((ref.get('external_id') for ref in obj.get('external_references', []) 
                                      if ref.get('source_name') == 'mitre-attack'), None)
                    if tactic_id:
                        self.tactics[tactic_id] = {
                            'id': tactic_id,
                            'name': obj.get('name', ''),
                            'description': obj.get('description', ''),
                            'reference': next((ref.get('url') for ref in obj.get('external_references', []) 
                                             if ref.get('source_name') == 'mitre-attack'), ''),
                            'stix_id': obj_id
                        }
                
                # Process techniques (attack-pattern)
                elif obj_type == 'attack-pattern':
                    technique_id = next((ref.get('external_id') for ref in obj.get('external_references', []) 
                                        if ref.get('source_name') == 'mitre-attack'), None)
                    if technique_id:
                        self.techniques[technique_id] = {
                            'id': technique_id,
                            'name': obj.get('name', ''),
                            'description': obj.get('description', ''),
                            'platforms': obj.get('x_mitre_platforms', []),
                            'detection': obj.get('x_mitre_detection', ''),
                            'reference': next((ref.get('url') for ref in obj.get('external_references', []) 
                                             if ref.get('source_name') == 'mitre-attack'), ''),
                            'stix_id': obj_id,
                            'mitigations': []  # Will be populated later using relationships
                        }
                
                # Process mitigations (course-of-action)
                elif obj_type == 'course-of-action':
                    mitigation_id = next((ref.get('external_id') for ref in obj.get('external_references', []) 
                                         if ref.get('source_name') == 'mitre-attack'), None)
                    if mitigation_id:
                        self.mitigations[mitigation_id] = {
                            'id': mitigation_id,
                            'name': obj.get('name', ''),
                            'description': obj.get('description', ''),
                            'reference': next((ref.get('url') for ref in obj.get('external_references', []) 
                                             if ref.get('source_name') == 'mitre-attack'), ''),
                            'stix_id': obj_id
                        }
                
                # Store relationships for later processing
                elif obj_type == 'relationship':
                    self.relationships.append({
                        'source_ref': obj.get('source_ref'),
                        'target_ref': obj.get('target_ref'),
                        'relationship_type': obj.get('relationship_type')
                    })
            
            # Process relationships to link mitigations to techniques
            self._process_relationships()
            
        except (FileNotFoundError, json.JSONDecodeError) as e:
            print(f"Error loading MITRE ATT&CK data: {e}")
    
    def _process_relationships(self):
        """Process relationships to link mitigations to techniques"""
        for rel in self.relationships:
            if rel.get('relationship_type') == 'mitigates':
                source_ref = rel.get('source_ref')  # Mitigation
                target_ref = rel.get('target_ref')  # Technique
                
                # Find the corresponding technique by STIX ID
                target_technique = None
                for tech_id, tech in self.techniques.items():
                    if tech.get('stix_id') == target_ref:
                        target_technique = tech
                        break
                
                # Find the corresponding mitigation by STIX ID
                source_mitigation = None
                for mit_id, mit in self.mitigations.items():
                    if mit.get('stix_id') == source_ref:
                        source_mitigation = mit
                        break
                
                # Link mitigation to technique
                if target_technique and source_mitigation:
                    target_technique['mitigations'].append(source_mitigation)
    
    def get_tactic(self, tactic_id):
        """Get tactic details by ID"""
        return self.tactics.get(tactic_id, {})
    
    def get_technique(self, technique_id):
        """Get technique details by ID"""
        return self.techniques.get(technique_id, {})
    
    def get_mitigation(self, mitigation_id):
        """Get mitigation details by ID"""
        return self.mitigations.get(mitigation_id, {})
    
    def get_mitigations_for_technique(self, technique_id):
        """Get all mitigations for a specific technique"""
        technique = self.get_technique(technique_id)
        return technique.get('mitigations', [])


class TheHiveQueries:
    
    @staticmethod
    def get_alerts(session) -> pd.DataFrame:
        """Get all alerts with basic information."""
        query = select(
            distinct(TheHiveAlert.id),
            TheHiveAlert.title,
            TheHiveAlert.description,
            TheHiveAlert.severity,
            TheHiveAlert.date,
            TheHiveAlert.source,
            TheHiveAlert.status
        ).order_by(TheHiveAlert.date.desc())
        
        return pd.read_sql(query, session.bind)
    
    @staticmethod
    def get_cases(session) -> pd.DataFrame:
        """Get all cases with basic information."""
        query = select(
            distinct(TheHiveCase.id),
            TheHiveCase.title,
            TheHiveCase.description,
            TheHiveCase.severity,
            TheHiveCase.start_date,
            TheHiveCase.end_date,
            TheHiveCase.owner,
            TheHiveCase.status,
            TheHiveCase.resolution_status
        ).order_by(TheHiveCase.start_date.desc())
        
        return pd.read_sql(query, session.bind)
    
    @staticmethod
    def get_artifacts(session) -> pd.DataFrame:
        """Get all artifacts with basic information."""
        query = select(
            distinct(TheHiveArtifact.id),
            TheHiveArtifact.data_type,
            TheHiveArtifact.data,
            TheHiveArtifact.message
        )
        
        return pd.read_sql(query, session.bind)
    
    @staticmethod
    def get_artifacts_by_host_ip(session, host_ip: str) -> pd.DataFrame:
        """Get artifacts associated with a specific host IP."""
        query = select(
            distinct(TheHiveArtifact.id),
            TheHiveArtifact.data_type,
            TheHiveArtifact.data,
            TheHiveArtifact.message
        ).join(
            alert_artifact_map,
            TheHiveArtifact.id == alert_artifact_map.c.artifact_id
        ).join(
            Host,
            TheHiveArtifact.data == func.split_part(Host.ip_address, '/', 1)
        ).where(
            and_(
                TheHiveArtifact.data_type == 'ip',
                func.split_part(Host.ip_address, '/', 1) == host_ip
            )
        )
        
        return pd.read_sql(query, session.bind)
    
    @staticmethod
    def get_alert_count(session) -> pd.DataFrame:
        """Get the total count of alerts."""
        query = select(
            func.count(TheHiveAlert.id).label('count')
        )
        
        return pd.read_sql(query, session.bind)
    
    @staticmethod
    def get_case_counts_by_status(session, status: str) -> pd.DataFrame:
        """
        Get the count of cases by a specific status.
        
        Args:
            session: SQLAlchemy session
            status: Status to filter by ('Open' or 'Resolved')
            
        Returns:
            DataFrame with count of cases matching the status
        """
        # Map the input status to the actual database value
        status_mapping = {
            'Open': 'Open',
            'Closed': 'Resolved'  # Map 'Closed' to 'Resolved'
        }
        
        db_status = status_mapping.get(status, status)
        
        query = select(
            func.count(TheHiveCase.id).label('count')
        ).where(
            TheHiveCase.status == db_status
        )
        
        return pd.read_sql(query, session.bind)
    
    @staticmethod
    def get_avg_resolution_time(session) -> pd.DataFrame:
        """
        Calculate the average case resolution time in seconds.
        For cases with null end_date, current timestamp is used.
        Returns the result as a formatted string representing days, hours, minutes.
        """
        # Use raw SQL for the interval calculation to avoid SQLAlchemy compatibility issues
        query = text("""
            SELECT 
                AVG(
                    CASE 
                        WHEN thehive_case.end_date IS NOT NULL THEN 
                            EXTRACT(EPOCH FROM (thehive_case.end_date - thehive_case.start_date))
                        ELSE 
                            EXTRACT(EPOCH FROM (CURRENT_TIMESTAMP - thehive_case.start_date))
                    END
                ) AS avg_seconds,
                EXTRACT(DAY FROM (
                    AVG(
                        CASE 
                            WHEN thehive_case.end_date IS NOT NULL THEN 
                                thehive_case.end_date - thehive_case.start_date
                            ELSE 
                                CURRENT_TIMESTAMP - thehive_case.start_date
                        END
                    )
                )) || ' days ' ||
                EXTRACT(HOUR FROM (
                    AVG(
                        CASE 
                            WHEN thehive_case.end_date IS NOT NULL THEN 
                                thehive_case.end_date - thehive_case.start_date
                            ELSE 
                                CURRENT_TIMESTAMP - thehive_case.start_date
                        END
                    )
                )) || ' hrs ' ||
                EXTRACT(MINUTE FROM (
                    AVG(
                        CASE 
                            WHEN thehive_case.end_date IS NOT NULL THEN 
                                thehive_case.end_date - thehive_case.start_date
                            ELSE 
                                CURRENT_TIMESTAMP - thehive_case.start_date
                        END
                    )
                )) || ' mins' AS avg_resolution_time
            FROM thehive_case
            WHERE thehive_case.start_date IS NOT NULL
        """)
        
        return pd.read_sql(query, session.bind)
    
    @staticmethod
    def get_alert_distribution_by_rules(session) -> pd.DataFrame:
        """Get distribution of alerts grouped by sigma rules."""
        # Create a subquery for sigma rule mappings from artifacts
        query = select(
            SigmaRule.name.label('rule_name'),
            func.count(TheHiveAlert.id).label('count')
        ).join(
            alert_artifact_map, 
            TheHiveAlert.id == alert_artifact_map.c.alert_id
        ).join(
            TheHiveArtifact, 
            alert_artifact_map.c.artifact_id == TheHiveArtifact.id
        ).join(
            SigmaRule, 
            TheHiveArtifact.data == SigmaRule.rule_kibana_id
        ).where(
            TheHiveArtifact.data_type == 'kibana-rule-id'
        ).group_by(
            SigmaRule.name
        ).order_by(
            func.count(TheHiveAlert.id).desc()
        )
        
        return pd.read_sql(query, session.bind)
    
    @staticmethod
    def get_alert_distribution_by_tactic(session) -> pd.DataFrame:
        """Get distribution of alerts grouped by MITRE tactics."""
        # Create a subquery for tactic mappings through sigma rules
        query = select(
            MitreTactic.name.label('tactic_name'),
            func.count(distinct(TheHiveAlert.id)).label('count')
        ).join(
            alert_artifact_map, 
            TheHiveAlert.id == alert_artifact_map.c.alert_id
        ).join(
            TheHiveArtifact, 
            alert_artifact_map.c.artifact_id == TheHiveArtifact.id
        ).join(
            SigmaRule, 
            TheHiveArtifact.data == SigmaRule.rule_kibana_id
        ).join(
            rule_tactics_map,
            SigmaRule.id == rule_tactics_map.c.sigma_rule_id
        ).join(
            MitreTactic,
            rule_tactics_map.c.tactic_id == MitreTactic.id
        ).where(
            TheHiveArtifact.data_type == 'kibana-rule-id'
        ).group_by(
            MitreTactic.name
        ).order_by(
            func.count(distinct(TheHiveAlert.id)).desc()
        )
        
        return pd.read_sql(query, session.bind)
    
    @staticmethod
    def get_most_common_observables(session) -> pd.DataFrame:
        """Get the most common observables (artifacts) across all alerts."""
        query = select(
            TheHiveArtifact.data_type,
            TheHiveArtifact.data,
            func.count(distinct(TheHiveAlert.id)).label('count')
        ).join(
            alert_artifact_map,
            TheHiveArtifact.id == alert_artifact_map.c.artifact_id
        ).join(
            TheHiveAlert,
            alert_artifact_map.c.alert_id == TheHiveAlert.id
        ).group_by(
            TheHiveArtifact.data_type,
            TheHiveArtifact.data
        ).order_by(
            func.count(distinct(TheHiveAlert.id)).desc()
        )
        
        return pd.read_sql(query, session.bind)
    
    @staticmethod
    def get_case_distribution_by_tags(session) -> pd.DataFrame:
        """
        Get distribution of cases grouped by tags.
        Excludes 'elastalert' and 'kibana-alert' tags.
        """
        # Since tags are stored as a JSON string, we need to unnest them first
        # This approach depends on PostgreSQL's JSON functions
        query = text("""
            SELECT 
                tag, 
                COUNT(*) as count
            FROM 
                thehive_case,
                jsonb_array_elements_text(tags::jsonb) as tag
            WHERE
                tag NOT IN ('elastalert', 'kibana-alert')
            GROUP BY 
                tag
            ORDER BY 
                count DESC
        """)
        
        return pd.read_sql(query, session.bind)
    
    @staticmethod
    def get_case_distribution_by_status(session) -> pd.DataFrame:
        """Get distribution of cases grouped by status."""
        query = select(
            TheHiveCase.status,
            func.count(TheHiveCase.id).label('count')
        ).group_by(
            TheHiveCase.status
        ).order_by(
            func.count(TheHiveCase.id).desc()
        )
        
        return pd.read_sql(query, session.bind)
    
    @staticmethod
    def get_closed_cases_by_resolution_type(session) -> pd.DataFrame:
        """Get distribution of closed cases grouped by resolution type."""
        query = select(
            TheHiveCase.resolution_status,
            func.count(TheHiveCase.id).label('count')
        ).where(
            TheHiveCase.status == 'Resolved'
        ).group_by(
            TheHiveCase.resolution_status
        ).order_by(
            func.count(TheHiveCase.id).desc()
        )
        
        return pd.read_sql(query, session.bind)
    
    @staticmethod
    def get_case_distribution_by_assignee(session) -> pd.DataFrame:
        """Get distribution of cases grouped by assignee (owner)."""
        query = select(
            TheHiveCase.owner,
            func.count(TheHiveCase.id).label('count')
        ).group_by(
            TheHiveCase.owner
        ).order_by(
            func.count(TheHiveCase.id).desc()
        )
        
        return pd.read_sql(query, session.bind)
    
    @staticmethod
    def get_case_distribution_by_observable_count(session) -> pd.DataFrame:
        """Get distribution of cases by number of observables."""
        # Use raw SQL for complex subqueries
        query = text("""
        -- Get the count of observables per case
        WITH observable_counts AS (
            SELECT 
                thehive_alert.case_id,
                COUNT(DISTINCT thehive_artifact.id) AS observable_count
            FROM 
                thehive_alert
            JOIN 
                thehive_alert_artifact_map ON thehive_alert.id = thehive_alert_artifact_map.alert_id
            JOIN 
                thehive_artifact ON thehive_alert_artifact_map.artifact_id = thehive_artifact.id
            WHERE 
                thehive_alert.case_id IS NOT NULL
            GROUP BY 
                thehive_alert.case_id
        )

        -- Main query
        SELECT 
            thehive_case.id AS case_id,
            thehive_case.title,
            observable_counts.observable_count
        FROM 
            thehive_case
        JOIN 
            observable_counts ON thehive_case.id = observable_counts.case_id
        ORDER BY 
            observable_counts.observable_count DESC
        """)
        
        return pd.read_sql(query, session.bind)
        
    @staticmethod
    def get_all_hosts(session) -> pd.DataFrame:
        """Get a list of all hosts."""
        query = select(
            Host.id,
            Host.hostname,
            Host.ip_address
        ).order_by(
            Host.hostname
        )
        
        return pd.read_sql(query, session.bind)
    
    @staticmethod
    def get_alerts_by_host_ip(session, host_ip: str) -> pd.DataFrame:
        """
        Get all alerts associated with a specific host IP.
        
        Args:
            session: SQLAlchemy session
            host_ip: IP address of the host (without subnet mask)
            
        Returns:
            DataFrame containing all alerts for the specified host
        """
        # Use raw SQL with parameter binding for more reliable execution
        query = text("""
        -- Create a subquery for host artifacts
        WITH host_artifacts AS (
            SELECT DISTINCT
                thehive_artifact.id AS artifact_id,
                thehive_artifact.data AS ip_address,
                host.id AS host_id,
                host.hostname
            FROM
                thehive_artifact
            JOIN
                host ON thehive_artifact.data = split_part(host.ip_address, '/', 1)
            WHERE
                thehive_artifact.data_type = 'ip'
                AND split_part(host.ip_address, '/', 1) = :host_ip
            )

        -- Main query to get alerts
        SELECT DISTINCT
            thehive_alert.id AS alert_id,
            thehive_alert.title,
            thehive_alert.description,
            thehive_alert.severity,
            thehive_alert.date,
            thehive_alert.source,
            thehive_alert.status,
            host_artifacts.hostname,
            host_artifacts.ip_address
        FROM
            thehive_alert
        JOIN 
            thehive_alert_artifact_map ON thehive_alert.id = thehive_alert_artifact_map.alert_id
        JOIN
            thehive_artifact ON thehive_alert_artifact_map.artifact_id = thehive_artifact.id
        JOIN
            host_artifacts ON thehive_artifact.id = host_artifacts.artifact_id
        ORDER BY
            thehive_alert.date DESC
        """)
        
        # Execute query with parameters
        df = pd.read_sql(query, session.bind, params={"host_ip": host_ip})
        
        # Additional deduplication in pandas to ensure no duplicates
        return df.drop_duplicates(subset=['alert_id'])
    
    @staticmethod
    def get_cases_by_host_ip(session, host_ip: str) -> pd.DataFrame:
        """
        Get all cases associated with a specific host IP and map them to SigmaRules.
        
        Args:
            session: SQLAlchemy session
            host_ip: IP address of the host (without subnet mask)
            
        Returns:
            DataFrame containing all cases for the specified host with SigmaRule mappings
        """
        # Use raw SQL with parameter binding for more reliable execution
        query = text("""
        -- Create a subquery for host artifacts
        WITH host_artifacts AS (
            SELECT DISTINCT
                thehive_artifact.id AS artifact_id,
                thehive_artifact.data AS ip_address,
                host.id AS host_id,
                host.hostname
            FROM
                thehive_artifact
            JOIN
                host ON thehive_artifact.data = split_part(host.ip_address, '/', 1)
            WHERE
                thehive_artifact.data_type = 'ip'
                AND split_part(host.ip_address, '/', 1) = :host_ip
        ),
        -- Create a subquery for host alerts
        host_alerts AS (
            SELECT DISTINCT
                thehive_alert.id AS alert_id,
                thehive_alert.case_id,
                host_artifacts.hostname,
                host_artifacts.ip_address
            FROM
                thehive_alert
            JOIN
                thehive_alert_artifact_map ON thehive_alert.id = thehive_alert_artifact_map.alert_id
            JOIN
                host_artifacts ON thehive_alert_artifact_map.artifact_id = host_artifacts.artifact_id
            WHERE
                thehive_alert.case_id IS NOT NULL
        ),
        -- Create a subquery for sigma rule mappings
        sigma_mappings AS (
            SELECT DISTINCT
                thehive_alert.id AS alert_id,
                thehive_alert.case_id,
                sigma_rule.id AS sigma_id,
                sigma_rule.rule_id,
                sigma_rule.name AS sigma_name,
                sigma_rule.description AS sigma_description,
                sigma_rule.severity AS sigma_severity
            FROM
                thehive_alert
            JOIN
                thehive_alert_artifact_map ON thehive_alert.id = thehive_alert_artifact_map.alert_id
            JOIN
                thehive_artifact ON thehive_alert_artifact_map.artifact_id = thehive_artifact.id
            JOIN
                sigma_rule ON thehive_artifact.data = sigma_rule.rule_id
            WHERE
                thehive_artifact.data_type = 'kibana-rule-id'
                AND thehive_alert.case_id IS NOT NULL
        )
        -- Main query to get cases with sigma rules
        SELECT DISTINCT
            thehive_case.id AS case_id,
            thehive_case.hive_id,
            thehive_case.title AS case_title,
            thehive_case.description AS case_description,
            thehive_case.severity AS case_severity,
            thehive_case.start_date,
            thehive_case.end_date,
            thehive_case.status AS case_status,
            thehive_case.resolution_status,
            host_alerts.hostname,
            host_alerts.ip_address,
            sigma_mappings.sigma_id,
            sigma_mappings.rule_id AS sigma_rule_id,
            sigma_mappings.sigma_name,
            sigma_mappings.sigma_severity
        FROM
            thehive_case
        JOIN
            host_alerts ON thehive_case.id = host_alerts.case_id
        LEFT JOIN
            sigma_mappings ON thehive_case.id = sigma_mappings.case_id
        ORDER BY
            thehive_case.start_date DESC
        """)
        
        # Execute query with parameters
        df = pd.read_sql(query, session.bind, params={"host_ip": host_ip})
        
        # Additional deduplication in pandas to handle any remaining duplicates
        return df.drop_duplicates(subset=['case_id'])
    
    @staticmethod
    def get_alert_distribution_by_host(session) -> pd.DataFrame:
        """Get distribution of alerts grouped by host."""
        # Use raw SQL for more reliable execution
        query = text("""
        SELECT DISTINCT
            host.hostname,
            COUNT(DISTINCT thehive_alert.id) AS alert_count
        FROM 
            host
        JOIN 
            thehive_artifact ON split_part(host.ip_address, '/', 1) = thehive_artifact.data
        JOIN 
            thehive_alert_artifact_map ON thehive_artifact.id = thehive_alert_artifact_map.artifact_id
        JOIN 
            thehive_alert ON thehive_alert_artifact_map.alert_id = thehive_alert.id
        WHERE 
            thehive_artifact.data_type = 'ip'
        GROUP BY 
            host.hostname
        ORDER BY 
            COUNT(DISTINCT thehive_alert.id) DESC
        """)
        
        return pd.read_sql(query, session.bind)
    
    @staticmethod
    def get_case_distribution_by_host(session) -> pd.DataFrame:
        """Get distribution of cases grouped by host."""
        # Use raw SQL for more reliable execution
        query = text("""
        SELECT DISTINCT
            host.hostname,
            COUNT(DISTINCT thehive_case.id) AS case_count
        FROM 
            host
        JOIN 
            thehive_artifact ON split_part(host.ip_address, '/', 1) = thehive_artifact.data
        JOIN 
            thehive_alert_artifact_map ON thehive_artifact.id = thehive_alert_artifact_map.artifact_id
        JOIN 
            thehive_alert ON thehive_alert_artifact_map.alert_id = thehive_alert.id
        JOIN 
            thehive_case ON thehive_alert.case_id = thehive_case.id
        WHERE 
            thehive_artifact.data_type = 'ip'
            AND thehive_alert.case_id IS NOT NULL
        GROUP BY 
            host.hostname
        ORDER BY 
            COUNT(DISTINCT thehive_case.id) DESC
        """)
        
        return pd.read_sql(query, session.bind)
    
    @staticmethod
    def get_mitre_details_for_alert(session, alert_id: int) -> dict:
        """
        Get MITRE ATT&CK details for a specific alert, including tactics, techniques, and mitigations
        
        Args:
            session: SQLAlchemy session
            alert_id: The ID of the alert
            
        Returns:
            Dictionary containing MITRE ATT&CK details for the alert
        """
        # Initialize the return structure
        mitre_details = {
            "tactics": [],
            "techniques": [],
            "mitigations": []
        }
        
        # Get rule ID associated with this alert
        query = text("""
        SELECT 
            sigma_rule.id AS rule_id,
            sigma_rule.name AS rule_name,
            sigma_rule.rule_id AS kibana_rule_id
        FROM 
            thehive_alert
        JOIN 
            thehive_alert_artifact_map ON thehive_alert.id = thehive_alert_artifact_map.alert_id
        JOIN 
            thehive_artifact ON thehive_alert_artifact_map.artifact_id = thehive_artifact.id
        JOIN 
            sigma_rule ON thehive_artifact.data = sigma_rule.rule_kibana_id
        WHERE 
            thehive_alert.id = :alert_id
            AND thehive_artifact.data_type = 'kibana-rule-id'
        LIMIT 1
        """)
        
        result = session.execute(query, {"alert_id": alert_id}).fetchone()
        if not result:
            return mitre_details
        
        rule_id = result.rule_id
        
        # Get tactics for this rule
        tactics_query = text("""
        SELECT 
            mt.id AS tactic_id,
            mt.tactic_id AS mitre_tactic_id,
            mt.name AS tactic_name,
            mt.reference AS tactic_reference
        FROM 
            mitre_tactic mt
        JOIN 
            mitre_tactic_sigma_rule mtsr ON mt.id = mtsr.tactic_id
        WHERE 
            mtsr.sigma_rule_id = :rule_id
        """)
        
        tactics = session.execute(tactics_query, {"rule_id": rule_id}).fetchall()
        
        # Use sets to track unique tactics by ID
        seen_tactic_ids = set()
        
        # Try to load MITRE ATT&CK data
        try:
            mitre_data = MitreAttackData.get_instance()
            
            # Process tactics
            for tactic in tactics:
                tactic_id = tactic.mitre_tactic_id
                if tactic_id not in seen_tactic_ids:
                    seen_tactic_ids.add(tactic_id)
                    
                    # Get tactic details from MITRE data
                    tactic_details = mitre_data.get_tactic(tactic_id)
                    
                    mitre_details["tactics"].append({
                        "id": tactic_id,
                        "name": tactic.tactic_name,
                        "reference": tactic.tactic_reference,
                        "description": tactic_details.get('description', '')
                    })
            
            # Get techniques for this rule
            techniques_query = text("""
            SELECT 
                mt.id AS technique_id,
                mt.technique_id AS mitre_technique_id,
                mt.name AS technique_name,
                mt.reference AS technique_reference
            FROM 
                mitre_technique mt
            JOIN 
                mitre_technique_sigma_rule mtsr ON mt.id = mtsr.technique_id
            WHERE 
                mtsr.sigma_rule_id = :rule_id
            """)
            
            techniques = session.execute(techniques_query, {"rule_id": rule_id}).fetchall()
            
            # Use sets to track unique techniques by ID
            seen_technique_ids = set()
            seen_mitigation_ids = set()
            
            # Process techniques
            for technique in techniques:
                technique_id = technique.mitre_technique_id
                
                # Skip if we've already processed this technique
                if technique_id in seen_technique_ids:
                    continue
                    
                seen_technique_ids.add(technique_id)
                
                # Get technique details from MITRE data
                technique_details = mitre_data.get_technique(technique_id)
                
                technique_info = {
                    "id": technique_id,
                    "name": technique.technique_name,
                    "reference": technique.technique_reference,
                    "description": technique_details.get('description', ''),
                    "platforms": technique_details.get('platforms', []),
                    "detection": technique_details.get('detection', '')
                }
                
                mitre_details["techniques"].append(technique_info)
                
                # Get mitigations for this technique
                mitigations = mitre_data.get_mitigations_for_technique(technique_id)
                
                for mitigation in mitigations:
                    mitigation_id = mitigation.get('id', '')
                    
                    # Skip if we've already processed this mitigation
                    if mitigation_id in seen_mitigation_ids:
                        continue
                        
                    seen_mitigation_ids.add(mitigation_id)
                    
                    mitre_details["mitigations"].append({
                        "id": mitigation_id,
                        "name": mitigation.get('name', ''),
                        "description": mitigation.get('description', ''),
                        "reference": mitigation.get('reference', '')
                    })
                    
        except Exception as e:
            print(f"Error processing MITRE data: {e}")
            
            # Fallback to basic information if MITRE data loading fails
            for tactic in tactics:
                tactic_id = tactic.mitre_tactic_id
                if tactic_id not in seen_tactic_ids:
                    seen_tactic_ids.add(tactic_id)
                    mitre_details["tactics"].append({
                        "id": tactic_id,
                        "name": tactic.tactic_name,
                        "reference": tactic.tactic_reference
                    })
            
            # Get techniques without MITRE data
            techniques_query = text("""
            SELECT 
                mt.id AS technique_id,
                mt.technique_id AS mitre_technique_id,
                mt.name AS technique_name,
                mt.reference AS technique_reference
            FROM 
                mitre_technique mt
            JOIN 
                mitre_technique_sigma_rule mtsr ON mt.id = mtsr.technique_id
            WHERE 
                mtsr.sigma_rule_id = :rule_id
            """)
            
            techniques = session.execute(techniques_query, {"rule_id": rule_id}).fetchall()
            
            # Use sets to track unique techniques by ID
            seen_technique_ids = set()
            
            for technique in techniques:
                technique_id = technique.mitre_technique_id
                
                # Skip if we've already processed this technique
                if technique_id in seen_technique_ids:
                    continue
                    
                seen_technique_ids.add(technique_id)
                
                mitre_details["techniques"].append({
                    "id": technique_id,
                    "name": technique.technique_name,
                    "reference": technique.technique_reference
                })
        
        return mitre_details
    
    @staticmethod
    def get_mitre_details_for_case(session, case_id: int) -> dict:
        """
        Get MITRE ATT&CK details for a specific case by gathering data from all related alerts
        
        Args:
            session: SQLAlchemy session
            case_id: The ID of the case
            
        Returns:
            Dictionary containing MITRE ATT&CK details for the case
        """
        # Initialize the return structure
        mitre_details = {
            "tactics": [],
            "techniques": [],
            "mitigations": []
        }
        
        # Get all alerts for this case
        query = text("""
        SELECT id 
        FROM thehive_alert 
        WHERE case_id = :case_id
        """)
        
        alerts = session.execute(query, {"case_id": case_id}).fetchall()
        
        # Deduplicate tactics, techniques, and mitigations
        seen_tactic_ids = set()
        seen_technique_ids = set()
        seen_mitigation_ids = set()
        
        # Get MITRE details for each alert
        for alert in alerts:
            alert_details = TheHiveQueries.get_mitre_details_for_alert(session, alert.id)
            
            # Process tactics
            for tactic in alert_details["tactics"]:
                tactic_id = tactic["id"]
                if tactic_id not in seen_tactic_ids:
                    seen_tactic_ids.add(tactic_id)
                    mitre_details["tactics"].append(tactic)
            
            # Process techniques
            for technique in alert_details["techniques"]:
                technique_id = technique["id"]
                if technique_id not in seen_technique_ids:
                    seen_technique_ids.add(technique_id)
                    mitre_details["techniques"].append(technique)
            
            # Process mitigations
            for mitigation in alert_details["mitigations"]:
                mitigation_id = mitigation["id"]
                if mitigation_id not in seen_mitigation_ids:
                    seen_mitigation_ids.add(mitigation_id)
                    mitre_details["mitigations"].append(mitigation)
        
        return mitre_details
    
    
    
    
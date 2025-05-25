from sqlalchemy import func, case, literal_column, and_, select, over, not_, distinct
from sqlalchemy.orm import aliased
from app.db.models import (
    Host, 
    HostConfigReview, 
    HostSigmaCompliance, 
    SigmaRule,
    SigmaWindowsLogSource,
    MitreTactic,
    MitreTechnique,
    MitreSubtechnique,
    sigma_rule_windows_log_map,
    rule_tactics_map,
    rule_techniques_map,
    rule_subtechniques_map,
    HostConfigReviewEntry
)

class HostQueries:
    
    @staticmethod
    def get_host_unnecessary_log_channels(session, host_id: int):
        """
        Get unnecessary log channels for a specific host.
        
        This function identifies Windows event log channels that are configured on
        the host but not required by any Sigma rules.
        
        Args:
            session: The database session
            host_id: The ID of the host to check
            
        Returns:
            A list of dictionaries containing information about unnecessary log channels
        """
        # Get the host with the latest config review
        host = session.query(Host).filter(Host.id == host_id).first()
        
        if not host or not host.latest_host_config_review_id:
            return []
            
        # Get all log channels configured on the host from the latest review
        host_channels = session.query(HostConfigReviewEntry.name, HostConfigReviewEntry.event_id).\
            filter(HostConfigReviewEntry.host_config_review_id == host.latest_host_config_review_id).\
            all()
            
        if not host_channels:
            return []
            
        # Convert to a set for easier comparison
        host_channel_names = {channel.name for channel in host_channels}
        
        # Get all required log channels from Sigma rules
        # This query collects all distinct Windows event channels that are needed by any Sigma rule
        required_channels = session.query(distinct(SigmaWindowsLogSource.windows_event_channel)).\
            join(SigmaRule.windows_log_sources).\
            filter(SigmaRule.enabled == True).\
            filter(SigmaRule.deleted == False).\
            all()
            
        # Convert to a set of channel names
        required_channel_names = {channel[0] for channel in required_channels}
        
        # Find channels configured on the host but not required by any Sigma rule
        unnecessary_channels = host_channel_names - required_channel_names
        
        # Query unnecessary channels with their event IDs
        result = session.query(HostConfigReviewEntry.name, HostConfigReviewEntry.event_id).\
            filter(HostConfigReviewEntry.host_config_review_id == host.latest_host_config_review_id).\
            filter(HostConfigReviewEntry.name.in_(unnecessary_channels)).\
            all()
            
        return result
    
    @staticmethod
    def get_all_compliant_rules_with_event_log_channels(session, host_id: int):
        """
        Get all compliant rules with their associated event log channels for a specific host.
        """
        # Create subquery for latest compliance review
        latest_compliance_review = (
            session.query(func.max(HostSigmaCompliance.host_config_review_id).label('id'))
            .filter(HostSigmaCompliance.host_id == host_id)
            .subquery()
        )

        # Aliases for MITRE tables to handle multiple joins
        MitreSubtechniqueAlias = aliased(MitreSubtechnique)

        # Main query
        query = (
            session.query(
                Host.id.label('host_id'),
                Host.hostname,
                Host.ip_address,
                SigmaRule.rule_id,
                SigmaRule.name.label('rule_name'),
                SigmaRule.log_source_category,
                SigmaRule.log_source_product,
                SigmaRule.level,
                SigmaWindowsLogSource.windows_event_channel,
                SigmaWindowsLogSource.event_id.label('windows_event_id'),
                MitreTactic.name.label('mitre_tactic'),
                MitreTactic.tactic_id.label('mitre_tactic_id'),
                MitreTechnique.name.label('mitre_technique'),
                MitreTechnique.technique_id.label('mitre_technique_id'),
                MitreSubtechniqueAlias.name.label('mitre_subtechnique'),
                MitreSubtechniqueAlias.subtechnique_id.label('mitre_subtechnique_id')
            )
            .join(HostConfigReview, Host.id == HostConfigReview.host_id)
            .join(latest_compliance_review, HostConfigReview.id == latest_compliance_review.c.id)
            .join(HostSigmaCompliance, and_(
                HostConfigReview.id == HostSigmaCompliance.host_config_review_id,
                Host.id == HostSigmaCompliance.host_id
            ))
            .join(SigmaRule, HostSigmaCompliance.sigma_id == SigmaRule.id)
            # Windows log sources - left joins
            .outerjoin(sigma_rule_windows_log_map, SigmaRule.id == sigma_rule_windows_log_map.c.sigma_rule_id)
            .outerjoin(SigmaWindowsLogSource, sigma_rule_windows_log_map.c.windows_log_source_id == SigmaWindowsLogSource.id)
            # MITRE tactics - left joins
            .outerjoin(rule_tactics_map, SigmaRule.id == rule_tactics_map.c.sigma_rule_id)
            .outerjoin(MitreTactic, rule_tactics_map.c.tactic_id == MitreTactic.id)
            # MITRE techniques - left joins
            .outerjoin(rule_techniques_map, SigmaRule.id == rule_techniques_map.c.sigma_rule_id)
            .outerjoin(MitreTechnique, rule_techniques_map.c.technique_id == MitreTechnique.id)
            # MITRE subtechniques - left joins
            .outerjoin(rule_subtechniques_map, SigmaRule.id == rule_subtechniques_map.c.sigma_rule_id)
            .outerjoin(
                MitreSubtechniqueAlias,
                and_(
                    rule_subtechniques_map.c.subtechnique_id == MitreSubtechniqueAlias.id,
                    (MitreSubtechniqueAlias.technique_id == MitreTechnique.id) | (MitreTechnique.id == None)
                )
            )
            .filter(Host.id == host_id)
            .order_by(
                SigmaRule.name,
                MitreTactic.name,
                MitreTechnique.name,
                MitreSubtechniqueAlias.name
            )
        )
        
        return query.all()

    @staticmethod
    def get_missing_rules_with_event_log_channels(session, host_id: int):
        """
        Get missing rules with their associated event log channels for a specific host.
        """
        # Subquery for compliant rules
        compliant_rules = (
            session.query(HostSigmaCompliance.sigma_id)
            .filter(
                HostSigmaCompliance.host_id == host_id,
                HostSigmaCompliance.host_config_review_id == (
                    session.query(Host.latest_host_config_review_id)
                    .filter(Host.id == host_id)
                    .scalar_subquery()
                )
            )
            .subquery()
        )

        # Case expression for sigma_log_source
        sigma_log_source = case(
            (
                and_(
                    SigmaRule.log_source_category != None,
                    SigmaRule.log_source_category != ''
                ),
                SigmaRule.log_source_category
            ),
            (
                and_(
                    SigmaRule.log_source_service != None,
                    SigmaRule.log_source_service != ''
                ),
                SigmaRule.log_source_service
            ),
            else_=None
        ).label('sigma_log_source')
        
        # Case expression for sorting by event_id presence
        event_id_sort_criteria = case(
            (SigmaWindowsLogSource.event_id != None, 0),
            else_=1
        )

        # Use window function to apply row_number()
        row_number = func.row_number().over(
            partition_by=[SigmaRule.id, sigma_log_source],
            order_by=[
                event_id_sort_criteria,
                SigmaWindowsLogSource.event_id
            ]
        ).label('rn')

        # Subquery with window function
        base_query = (
            session.query(
                SigmaRule.id.label('sigma_rule_id'),
                SigmaRule.name.label('sigma_name'),
                sigma_log_source,
                SigmaRule.log_source_product,
                SigmaRule.level.label('sigma_level'),
                SigmaWindowsLogSource.windows_event_channel,
                SigmaWindowsLogSource.event_id.label('windows_event_id'),
                row_number
            )
            .outerjoin(sigma_rule_windows_log_map, SigmaRule.id == sigma_rule_windows_log_map.c.sigma_rule_id)
            .outerjoin(SigmaWindowsLogSource, sigma_rule_windows_log_map.c.windows_log_source_id == SigmaWindowsLogSource.id)
            .filter(
                ~SigmaRule.id.in_(compliant_rules),
                SigmaRule.deleted == False,
                SigmaRule.enabled == True
            )
            .subquery()
        )

        # Main query selecting only rn = 1
        query = (
            session.query(
                base_query.c.sigma_rule_id,
                base_query.c.sigma_name,
                base_query.c.sigma_log_source,
                base_query.c.log_source_product,
                base_query.c.sigma_level,
                base_query.c.windows_event_channel,
                base_query.c.windows_event_id
            )
            .filter(base_query.c.rn == 1)
        )
        
        return query.all()

    @staticmethod
    def get_host_compliant_noncompliant_rules_universal(session, host_id: int, compliant: bool = False):
        """
        Get rules with their associated event log channels for a specific host.
        
        Args:
            session: SQLAlchemy database session
            host_id: ID of the host to query
            compliant: If True, returns compliant rules; if False, returns non-compliant rules
        
        Returns:
            List of rule details with their associated event log channels
        """
        # Subquery for compliant rules - using SQLAlchemy 2.0 style
        compliant_rules_stmt = (
            select(HostSigmaCompliance.sigma_id)
            .where(
                HostSigmaCompliance.host_id == host_id,
                HostSigmaCompliance.host_config_review_id == (
                    select(Host.latest_host_config_review_id)
                    .where(Host.id == host_id)
                    .scalar_subquery()
                )
            )
        )
        
        # Get the IDs directly as a list for the in_ operator
        compliant_rule_ids = session.scalars(compliant_rules_stmt).all()
        
        # Case expression for sigma_log_source
        sigma_log_source = case(
            (
                and_(
                    SigmaRule.log_source_category != None,
                    SigmaRule.log_source_category != ''
                ),
                SigmaRule.log_source_category
            ),
            (
                and_(
                    SigmaRule.log_source_service != None,
                    SigmaRule.log_source_service != ''
                ),
                SigmaRule.log_source_service
            ),
            else_=None
        ).label('sigma_log_source')
        
        # Build filter based on compliant parameter
        if compliant:
            compliance_filter = SigmaRule.id.in_(compliant_rule_ids)
        else:
            compliance_filter = ~SigmaRule.id.in_(compliant_rule_ids)
            
        # Base query with window function for row numbering
        base_query = (
            select(
                SigmaRule.id.label('sigma_rule_id'),
                SigmaRule.name.label('sigma_name'),
                sigma_log_source,
                SigmaRule.log_source_product,
                SigmaRule.level.label('sigma_level'),
                SigmaWindowsLogSource.windows_event_channel,
                SigmaWindowsLogSource.event_id.label('windows_event_id'),
                func.row_number().over(
                    partition_by=[SigmaRule.id, sigma_log_source],
                    order_by=[
                        case(
                            (SigmaWindowsLogSource.event_id != None, 0),
                            else_=1
                        ),
                        SigmaWindowsLogSource.event_id
                    ]
                ).label('rn')
            )
            .outerjoin(sigma_rule_windows_log_map, SigmaRule.id == sigma_rule_windows_log_map.c.sigma_rule_id)
            .outerjoin(SigmaWindowsLogSource, sigma_rule_windows_log_map.c.windows_log_source_id == SigmaWindowsLogSource.id)
            .where(
                compliance_filter,
                SigmaRule.deleted == False,
                SigmaRule.enabled == True
            )
            .subquery()
        )

        # Main query selecting only rn = 1
        query = (
            select(
                base_query.c.sigma_rule_id,
                base_query.c.sigma_name,
                base_query.c.sigma_log_source,
                base_query.c.log_source_product,
                base_query.c.sigma_level,
                base_query.c.windows_event_channel,
                base_query.c.windows_event_id
            )
            .where(base_query.c.rn == 1)
        )
        
        # Execute query using SQLAlchemy 2.0 style
        result = session.execute(query)
        return result.all()

    
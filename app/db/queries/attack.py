from sqlalchemy import func, distinct, case, literal, select, or_, and_
from sqlalchemy.sql import text

from app.db.models import (
    MitreTactic, MitreTechnique, MitreSubtechnique, SigmaRule,
    HostSigmaCompliance, Host, NetBoxTag, tag_device_rule_map,
    rule_tactics_map, rule_techniques_map, rule_subtechniques_map
)


class AttackMatrixQueries:
    """
    Class providing methods to query attack matrix data from the database using SQLAlchemy.
    All methods are static and return query results.
    """
    
    @staticmethod
    def get_filtered_hosts(session, filter_criteria):
        """
        Returns a list of host IDs matching the filter criteria.
        Args:
            session: SQLAlchemy session
            filter_criteria: see original docstring
        Returns:
            List of host IDs
        """
        host_query = session.query(Host.id)
        if isinstance(filter_criteria, dict):
            # Process column filters
            if 'columns' in filter_criteria:
                columns_dict = filter_criteria.get('columns', {})
                operator = filter_criteria.get('operator', 'AND')
                if columns_dict:
                    conditions = []
                    for column_name, values in columns_dict.items():
                        if hasattr(Host, column_name) and values:
                            if len(values) == 1:
                                column_condition = getattr(Host, column_name) == values[0]
                            else:
                                column_condition = getattr(Host, column_name).in_(values)
                            conditions.append(column_condition)
                    if conditions:
                        if operator.upper() == 'OR':
                            host_query = host_query.filter(or_(*conditions))
                        else:
                            host_query = host_query.filter(and_(*conditions))
            # Process tag filters if present
            if 'tags' in filter_criteria and filter_criteria['tags'].get('tag_ids'):
                tag_ids = filter_criteria['tags'].get('tag_ids', [])
                tag_operator = filter_criteria['tags'].get('operator', 'AND')
                if tag_ids:
                    if tag_operator.upper() == 'AND':
                        tag_count_subquery = (
                            session.query(
                                tag_device_rule_map.c.device_id.label('host_id'),
                                func.count(tag_device_rule_map.c.tag_id).label('tag_count')
                            )
                            .filter(tag_device_rule_map.c.tag_id.in_(tag_ids))
                            .group_by(tag_device_rule_map.c.device_id)
                            .having(func.count(tag_device_rule_map.c.tag_id) == len(tag_ids))
                            .subquery()
                        )
                        host_query = host_query.filter(
                            Host.id.in_(
                                select(tag_count_subquery.c.host_id)
                            )
                        )
                    else:
                        host_query = host_query.filter(
                            Host.id.in_(
                                select(tag_device_rule_map.c.device_id)
                                .where(tag_device_rule_map.c.tag_id.in_(tag_ids))
                            )
                        )
        else:
            for field, value in filter_criteria.items():
                host_query = host_query.filter(getattr(Host, field) == value)
        return [row.id for row in host_query.all()]

    @staticmethod
    def get_per_group_of_hosts_coverage(session, filter_criteria):
        """+
        Get coverage data for a group of hosts based on the given filter criteria.
        
        Args:
            session: SQLAlchemy session
            filter_criteria: A dictionary with:
                - columns: dict where keys are column names and values are lists of values
                - operator: "AND" or "OR" to combine conditions
                - tags: (optional) dict with tag_ids list and operator ("AND"/"OR")
            
        Returns:
            List of dictionaries with coverage data for each tactic, technique, and subtechnique
        """
        # Create a subquery to get the filtered host IDs
        host_query = session.query(Host.id)
        
        # Handle the more complex filter criteria structure
        if isinstance(filter_criteria, dict):
            # Process column filters
            if 'columns' in filter_criteria:
                columns_dict = filter_criteria.get('columns', {})
                operator = filter_criteria.get('operator', 'AND')
                
                if columns_dict:
                    conditions = []
                    
                    # Build a list of conditions for each column
                    for column_name, values in columns_dict.items():
                        if hasattr(Host, column_name) and values:
                            if len(values) == 1:
                                # For a single value, use equals
                                column_condition = getattr(Host, column_name) == values[0]
                            else:
                                # For multiple values, use IN
                                column_condition = getattr(Host, column_name).in_(values)
                            conditions.append(column_condition)
                    
                    # Apply conditions based on operator
                    if conditions:
                        if operator.upper() == 'OR':
                            host_query = host_query.filter(or_(*conditions))
                        else:  # AND is default
                            host_query = host_query.filter(and_(*conditions))
            
            # Process tag filters if present
            if 'tags' in filter_criteria and filter_criteria['tags'].get('tag_ids'):
                tag_ids = filter_criteria['tags'].get('tag_ids', [])
                tag_operator = filter_criteria['tags'].get('operator', 'AND')
                
                if tag_ids:
                    # Create a subquery for host IDs that have the specified tags
                    if tag_operator.upper() == 'AND':
                        # For AND: host must have ALL specified tags
                        # We count how many of the requested tags the host has
                        # and only include hosts where that count equals the total requested tags
                        tag_count_subquery = (
                            session.query(
                                tag_device_rule_map.c.device_id.label('host_id'),
                                func.count(tag_device_rule_map.c.tag_id).label('tag_count')
                            )
                            .filter(tag_device_rule_map.c.tag_id.in_(tag_ids))
                            .group_by(tag_device_rule_map.c.device_id)
                            .having(func.count(tag_device_rule_map.c.tag_id) == len(tag_ids))
                            .subquery()
                        )
                        
                        # Filter hosts to only those with all tags
                        host_query = host_query.filter(
                            Host.id.in_(
                                select(tag_count_subquery.c.host_id)
                            )
                        )
                    else:
                        # For OR: host must have ANY of the specified tags
                        host_query = host_query.filter(
                            Host.id.in_(
                                select(tag_device_rule_map.c.device_id)
                                .where(tag_device_rule_map.c.tag_id.in_(tag_ids))
                            )
                        )
        else:
            # Handle the original format for backward compatibility
            for field, value in filter_criteria.items():
                host_query = host_query.filter(getattr(Host, field) == value)
        
        host_subquery = host_query.subquery()
        
        # Count the total number of hosts in the filtered group
        total_hosts_count = session.query(func.count()).select_from(host_subquery).scalar()
        
        # If no hosts match the filter, return empty results with zero coverage
        if total_hosts_count == 0:
            empty_results = []
            # Get all tactics, techniques, and subtechniques used by enabled rules
            query = session.query(
                MitreTactic.tactic_id,
                MitreTechnique.technique_id,
                MitreSubtechnique.subtechnique_id,
                literal(0).label('covered_hosts'),
                literal(0).label('uncovered_hosts'),
                literal(0).label('total_hosts'),
                literal(0).label('coverage_percentage'),
                func.count(distinct(SigmaRule.id)).label('rule_count')
            ).join(
                rule_tactics_map, MitreTactic.id == rule_tactics_map.c.tactic_id
            ).join(
                SigmaRule, rule_tactics_map.c.sigma_rule_id == SigmaRule.id
            ).join(
                rule_techniques_map, SigmaRule.id == rule_techniques_map.c.sigma_rule_id
            ).join(
                MitreTechnique, rule_techniques_map.c.technique_id == MitreTechnique.id
            ).outerjoin(
                rule_subtechniques_map, SigmaRule.id == rule_subtechniques_map.c.sigma_rule_id
            ).outerjoin(
                MitreSubtechnique, rule_subtechniques_map.c.subtechnique_id == MitreSubtechnique.id
            ).filter(
                SigmaRule.enabled == True,
                SigmaRule.deleted == False
            ).group_by(
                MitreTactic.tactic_id, 
                MitreTechnique.technique_id, 
                MitreSubtechnique.subtechnique_id
            ).order_by(
                MitreTactic.tactic_id, 
                MitreTechnique.technique_id, 
                MitreSubtechnique.subtechnique_id
            )
            return query.all()
        
        # Main query
        query = session.query(
            MitreTactic.tactic_id,
            MitreTechnique.technique_id,
            MitreSubtechnique.subtechnique_id,
            func.count(distinct(HostSigmaCompliance.host_id)).label('covered_hosts'),
            (total_hosts_count - func.count(distinct(HostSigmaCompliance.host_id))).label('uncovered_hosts'),
            literal(total_hosts_count).label('total_hosts'),
            case(
                (total_hosts_count == 0, 0),
                else_=func.round(func.count(distinct(HostSigmaCompliance.host_id)) * 100.0 / total_hosts_count, 2)
            ).label('coverage_percentage'),
            func.count(distinct(SigmaRule.id)).label('rule_count')
        ).join(
            rule_tactics_map, MitreTactic.id == rule_tactics_map.c.tactic_id
        ).join(
            SigmaRule, rule_tactics_map.c.sigma_rule_id == SigmaRule.id
        ).join(
            rule_techniques_map, SigmaRule.id == rule_techniques_map.c.sigma_rule_id
        ).join(
            MitreTechnique, rule_techniques_map.c.technique_id == MitreTechnique.id
        ).outerjoin(
            rule_subtechniques_map, SigmaRule.id == rule_subtechniques_map.c.sigma_rule_id
        ).outerjoin(
            MitreSubtechnique, rule_subtechniques_map.c.subtechnique_id == MitreSubtechnique.id
        ).outerjoin(
            HostSigmaCompliance, 
            (SigmaRule.id == HostSigmaCompliance.sigma_id) & 
            (HostSigmaCompliance.host_id.in_(select(host_subquery.c.id)))
        ).filter(
            SigmaRule.enabled == True,
            SigmaRule.deleted == False
        ).group_by(
            MitreTactic.tactic_id, 
            MitreTechnique.technique_id, 
            MitreSubtechnique.subtechnique_id
        ).order_by(
            MitreTactic.tactic_id, 
            MitreTechnique.technique_id, 
            MitreSubtechnique.subtechnique_id
        )
        
        return query.all()

    @staticmethod
    def get_specific_host_coverage(session, host_id):
        """
        Get coverage data for a specific host.
        
        Args:
            session: SQLAlchemy session
            host_id: ID of the host to get coverage for
            
        Returns:
            List of dictionaries with coverage data for each tactic, technique, and subtechnique
        """
        query = session.query(
            MitreTactic.tactic_id,
            MitreTechnique.technique_id,
            MitreSubtechnique.subtechnique_id,
            # For specific host, covered_hosts is either 0 or 1
            case(
                (HostSigmaCompliance.id != None, 1),
                else_=0
            ).label('covered_hosts'),
            # For specific host, uncovered_hosts is either 0 or 1 (opposite of covered)
            case(
                (HostSigmaCompliance.id != None, 0),
                else_=1
            ).label('uncovered_hosts'),
            # Total hosts is always 1 for a specific host
            literal(1).label('total_hosts'),
            # Coverage percentage is either 0 or 100
            case(
                (HostSigmaCompliance.id != None, 100),
                else_=0
            ).label('coverage_percentage'),
            func.count(distinct(SigmaRule.id)).label('rule_count')
        ).join(
            rule_tactics_map, MitreTactic.id == rule_tactics_map.c.tactic_id
        ).join(
            SigmaRule, rule_tactics_map.c.sigma_rule_id == SigmaRule.id
        ).join(
            rule_techniques_map, SigmaRule.id == rule_techniques_map.c.sigma_rule_id
        ).join(
            MitreTechnique, rule_techniques_map.c.technique_id == MitreTechnique.id
        ).outerjoin(
            rule_subtechniques_map, SigmaRule.id == rule_subtechniques_map.c.sigma_rule_id
        ).outerjoin(
            MitreSubtechnique, rule_subtechniques_map.c.subtechnique_id == MitreSubtechnique.id
        ).outerjoin(
            HostSigmaCompliance, 
            (SigmaRule.id == HostSigmaCompliance.sigma_id) & 
            (HostSigmaCompliance.host_id == host_id)
        ).filter(
            SigmaRule.enabled == True,
            SigmaRule.deleted == False
        ).group_by(
            MitreTactic.tactic_id, 
            MitreTechnique.technique_id, 
            MitreSubtechnique.subtechnique_id, 
            HostSigmaCompliance.id
        ).order_by(
            MitreTactic.tactic_id, 
            MitreTechnique.technique_id, 
            MitreSubtechnique.subtechnique_id
        )
        
        return query.all()

    @staticmethod
    def get_all_hosts_coverage(session):
        """
        Get coverage data across all hosts.
        
        Args:
            session: SQLAlchemy session
            
        Returns:
            List of dictionaries with coverage data for each tactic, technique, and subtechnique
        """
        # Count the total number of hosts with config reviews
        total_hosts_count = session.query(func.count()).select_from(Host).filter(
            Host.latest_host_config_review_id != None
        ).scalar()
        
        # Main query
        query = session.query(
            MitreTactic.tactic_id,
            MitreTechnique.technique_id,
            MitreSubtechnique.subtechnique_id,
            func.count(distinct(HostSigmaCompliance.host_id)).label('covered_hosts'),
            (total_hosts_count - func.count(distinct(HostSigmaCompliance.host_id))).label('uncovered_hosts'),
            literal(total_hosts_count).label('total_hosts'),
            case(
                (total_hosts_count == 0, 0),
                else_=func.round(func.count(distinct(HostSigmaCompliance.host_id)) * 100.0 / total_hosts_count, 2)
            ).label('coverage_percentage'),
            func.count(distinct(SigmaRule.id)).label('rule_count')
        ).join(
            rule_tactics_map, MitreTactic.id == rule_tactics_map.c.tactic_id
        ).join(
            SigmaRule, rule_tactics_map.c.sigma_rule_id == SigmaRule.id
        ).join(
            rule_techniques_map, SigmaRule.id == rule_techniques_map.c.sigma_rule_id
        ).join(
            MitreTechnique, rule_techniques_map.c.technique_id == MitreTechnique.id
        ).outerjoin(
            rule_subtechniques_map, SigmaRule.id == rule_subtechniques_map.c.sigma_rule_id
        ).outerjoin(
            MitreSubtechnique, rule_subtechniques_map.c.subtechnique_id == MitreSubtechnique.id
        ).outerjoin(
            HostSigmaCompliance, SigmaRule.id == HostSigmaCompliance.sigma_id
        ).filter(
            SigmaRule.enabled == True,
            SigmaRule.deleted == False
        ).group_by(
            MitreTactic.tactic_id, 
            MitreTechnique.technique_id, 
            MitreSubtechnique.subtechnique_id
        ).order_by(
            MitreTactic.tactic_id, 
            MitreTechnique.technique_id, 
            MitreSubtechnique.subtechnique_id
        )
        
        return query.all()

    @staticmethod
    def get_all_implemented_rules(session):
        """
        Get all implemented and enabled rules.
        
        Args:
            session: SQLAlchemy session
            
        Returns:
            List of dictionaries with tactic, technique, and subtechnique IDs
        """
        query = session.query(
            MitreTactic.tactic_id,
            MitreTechnique.technique_id,
            MitreSubtechnique.subtechnique_id,
            # We don't have real covered hosts data, so set to None
            literal(None).label('covered_hosts'),
            # We don't have real uncovered hosts data, so set to None
            literal(None).label('uncovered_hosts'),
            # We don't have real total hosts data, so set to None
            literal(None).label('total_hosts'),
            # Static 100% coverage as in the original query
            literal(100.0).label('coverage_percentage'),
            func.count(distinct(SigmaRule.id)).label('rule_count')
        ).join(
            rule_tactics_map, MitreTactic.id == rule_tactics_map.c.tactic_id
        ).join(
            SigmaRule, rule_tactics_map.c.sigma_rule_id == SigmaRule.id
        ).join(
            rule_techniques_map, SigmaRule.id == rule_techniques_map.c.sigma_rule_id
        ).join(
            MitreTechnique, rule_techniques_map.c.technique_id == MitreTechnique.id
        ).outerjoin(
            rule_subtechniques_map, SigmaRule.id == rule_subtechniques_map.c.sigma_rule_id
        ).outerjoin(
            MitreSubtechnique, rule_subtechniques_map.c.subtechnique_id == MitreSubtechnique.id
        ).filter(
            SigmaRule.enabled == True,
            SigmaRule.deleted == False
        ).group_by(
            MitreTactic.tactic_id, 
            MitreTechnique.technique_id, 
            MitreSubtechnique.subtechnique_id
        ).order_by(
            MitreTactic.tactic_id, 
            MitreTechnique.technique_id, 
            MitreSubtechnique.subtechnique_id
        )
        
        return query.all()

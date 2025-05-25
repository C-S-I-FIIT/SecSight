from sqlalchemy import func, case, select, literal, distinct, desc, or_, and_, union_all, String, Float
from sqlalchemy.orm import aliased
from sqlalchemy.sql import text
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
    rule_subtechniques_map
)


class SigmaQueries:
    """
    Class providing methods to query Sigma rule data from the database using SQLAlchemy.
    """
    
    @staticmethod
    def get_host_rule_coverage(session):
        """
        Get the number of covered Sigma rules per host.
        
        Args:
            session: SQLAlchemy session
            
        Returns:
            List of tuples with hostname, ip_address, and covered_rules_count
        """
        # Create a subquery with the count to be able to ORDER BY it properly
        subquery = (
            select(
                Host.id,
                Host.hostname,
                Host.ip_address,
                func.count(distinct(HostSigmaCompliance.sigma_id)).label('covered_rules_count')
            )
            .select_from(Host)
            .outerjoin(
                HostConfigReview, 
                Host.latest_host_config_review_id == HostConfigReview.id
            )
            .outerjoin(
                HostSigmaCompliance, 
                and_(
                    HostConfigReview.id == HostSigmaCompliance.host_config_review_id,
                    Host.id == HostSigmaCompliance.host_id
                )
            )
            .group_by(
                Host.id, 
                Host.hostname, 
                Host.ip_address
            )
            .subquery()
        )
        
        # Final query using the subquery to order by the count
        query = (
            select(
                subquery.c.hostname,
                subquery.c.ip_address,
                subquery.c.covered_rules_count
            )
            .select_from(subquery)
            .order_by(
                desc(subquery.c.covered_rules_count)
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_no_rules_by_win_log_channel(session):
        """
        Get the number of Sigma rules per Windows Event Channel and Sigma log source.
        
        Args:
            session: SQLAlchemy session
            
        Returns:
            List of tuples with windows_event_channel, sigma_log_source, and rule_count
        """
        query = (
            select(
                SigmaWindowsLogSource.windows_event_channel,
                case(
                    (SigmaRule.log_source_category == '', SigmaRule.log_source_service),
                    else_=SigmaRule.log_source_category
                ).label('sigma_log_source'),
                func.count(distinct(SigmaRule.id)).label('rule_count')
            )
            .select_from(SigmaRule)
            .join(
                sigma_rule_windows_log_map,
                SigmaRule.id == sigma_rule_windows_log_map.c.sigma_rule_id
            )
            .join(
                SigmaWindowsLogSource,
                sigma_rule_windows_log_map.c.windows_log_source_id == SigmaWindowsLogSource.id
            )
            .where(
                or_(SigmaRule.deleted == False, SigmaRule.deleted == None)
            )
            .group_by(
                SigmaWindowsLogSource.windows_event_channel,
                SigmaRule.log_source_category,
                SigmaRule.log_source_service
            )
            .order_by(
                desc(func.count(distinct(SigmaRule.id))),
                SigmaWindowsLogSource.windows_event_channel,
                SigmaRule.log_source_category,
                SigmaRule.log_source_service
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_host_coverage_percentage(session):
        """
        Get the percentage of covered Sigma rules per host.
        
        Args:
            session: SQLAlchemy session
            
        Returns:
            List of tuples with hostname, ip_address, covered_rules_count, total_rules_count, and coverage_percentage
        """
        # Total non-deleted rules
        total_rules_subquery = (
            select(func.count().label('total_count'))
            .select_from(SigmaRule)
            .where(SigmaRule.deleted == False)
            .scalar_subquery()
        )
        
        # Host coverage
        host_coverage_subquery = (
            select(
                Host.id.label('host_id'),
                Host.hostname,
                Host.ip_address,
                func.count(distinct(HostSigmaCompliance.sigma_id)).label('covered_rules_count')
            )
            .select_from(Host)
            .outerjoin(
                HostConfigReview, 
                Host.latest_host_config_review_id == HostConfigReview.id
            )
            .outerjoin(
                HostSigmaCompliance, 
                and_(
                    HostConfigReview.id == HostSigmaCompliance.host_config_review_id,
                    Host.id == HostSigmaCompliance.host_id
                )
            )
            .group_by(
                Host.id, 
                Host.hostname, 
                Host.ip_address
            )
            .subquery()
        )
        
        # Final query with coverage percentage calculation
        coverage_query = (
            select(
                host_coverage_subquery.c.hostname,
                host_coverage_subquery.c.ip_address,
                host_coverage_subquery.c.covered_rules_count,
                total_rules_subquery.label('total_rules_count'),
                func.round(
                    (host_coverage_subquery.c.covered_rules_count * 100.0) / 
                    total_rules_subquery, 
                    2
                ).label('coverage_percentage')
            )
            .select_from(host_coverage_subquery)
            .subquery()
        )
        
        # Wrap in another query to be able to order by the calculated percentage
        query = (
            select(
                coverage_query.c.hostname,
                coverage_query.c.ip_address,
                coverage_query.c.covered_rules_count,
                coverage_query.c.total_rules_count,
                coverage_query.c.coverage_percentage
            )
            .select_from(coverage_query)
            .order_by(
                desc(coverage_query.c.coverage_percentage)
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_top_bottom_covered_rules(session, limit=10):
        """
        Get the top N most covered rules and bottom N least covered rules.
        
        Args:
            session: SQLAlchemy session
            limit: Number of top/bottom rules to retrieve (default: 10)
            
        Returns:
            List of tuples with rule_name, sigma_rule_id, compliant_hosts_count, and category
        """
        # Rule coverage count
        rule_coverage_subquery = (
            select(
                SigmaRule.id.label('rule_id'),
                SigmaRule.name.label('rule_name'),
                SigmaRule.rule_id.label('sigma_rule_id'),
                func.count(distinct(HostSigmaCompliance.host_id)).label('compliant_hosts_count')
            )
            .outerjoin(
                HostSigmaCompliance,
                SigmaRule.id == HostSigmaCompliance.sigma_id
            )
            .where(
                SigmaRule.deleted == False
            )
            .group_by(
                SigmaRule.id, 
                SigmaRule.name, 
                SigmaRule.rule_id
            )
            .subquery()
        )
        
        # Top N most covered rules
        most_covered = (
            select(
                rule_coverage_subquery.c.rule_name,
                rule_coverage_subquery.c.sigma_rule_id,
                rule_coverage_subquery.c.compliant_hosts_count,
                literal('Most Covered').label('category')
            )
            .order_by(
                desc(rule_coverage_subquery.c.compliant_hosts_count)
            )
            .limit(limit)
        )
        
        # Bottom N least covered rules (with at least one compliant host)
        least_covered = (
            select(
                rule_coverage_subquery.c.rule_name,
                rule_coverage_subquery.c.sigma_rule_id,
                rule_coverage_subquery.c.compliant_hosts_count,
                literal('Least Covered').label('category')
            )
            .where(
                rule_coverage_subquery.c.compliant_hosts_count > 0
            )
            .order_by(
                rule_coverage_subquery.c.compliant_hosts_count
            )
            .limit(limit)
        )
        
        # Combine the two queries
        combined_query = union_all(most_covered, least_covered)
        
        query = (
            select(
                combined_query.c.rule_name,
                combined_query.c.sigma_rule_id,
                combined_query.c.compliant_hosts_count,
                combined_query.c.category
            )
            .order_by(
                combined_query.c.category,
                desc(combined_query.c.compliant_hosts_count)
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_coverage_timeline(session):
        """
        Get a timeline of Sigma rule coverage percentage per host over time.
        
        Args:
            session: SQLAlchemy session
            
        Returns:
            List of tuples with hostname, review_date, covered_rules_count, total_rules_count, and coverage_percentage
        """
        # Total rules (excluding deleted)
        total_rules_subquery = (
            select(func.count().label('total_count'))
            .select_from(SigmaRule)
            .where(SigmaRule.deleted == False)
            .scalar_subquery()
        )
        
        # Host reviews with coverage counts
        host_reviews_subquery = (
            select(
                Host.id.label('host_id'),
                Host.hostname,
                HostConfigReview.id.label('review_id'),
                HostConfigReview.created_at,
                func.count(distinct(HostSigmaCompliance.sigma_id)).label('covered_rules_count')
            )
            .select_from(Host)
            .join(
                HostConfigReview, 
                Host.id == HostConfigReview.host_id
            )
            .outerjoin(
                HostSigmaCompliance, 
                and_(
                    HostConfigReview.id == HostSigmaCompliance.host_config_review_id,
                    Host.id == HostSigmaCompliance.host_id
                )
            )
            .group_by(
                Host.id, 
                Host.hostname, 
                HostConfigReview.id, 
                HostConfigReview.created_at
            )
            .subquery()
        )
        
        # Final query
        query = (
            select(
                host_reviews_subquery.c.hostname,
                host_reviews_subquery.c.created_at.label('review_date'),
                host_reviews_subquery.c.covered_rules_count,
                total_rules_subquery.label('total_rules_count'),
                func.round(
                    (host_reviews_subquery.c.covered_rules_count * 100.0) / 
                    total_rules_subquery, 
                    2
                ).label('coverage_percentage')
            )
            .select_from(host_reviews_subquery)
            .order_by(
                host_reviews_subquery.c.hostname,
                host_reviews_subquery.c.created_at
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_mitre_tactic_distribution(session):
        """
        Get the distribution of Sigma rules across MITRE tactics for a radar chart.
        
        Args:
            session: SQLAlchemy session
            
        Returns:
            List of tuples with tactic_name, tactic_id, and rule_count
        """
        # Create a subquery with the rule count per tactic
        tactic_count_subquery = (
            select(
                MitreTactic.name.label('tactic_name'),
                MitreTactic.tactic_id,
                func.count(distinct(SigmaRule.id)).label('rule_count')
            )
            .select_from(MitreTactic)
            .outerjoin(
                rule_tactics_map, 
                MitreTactic.id == rule_tactics_map.c.tactic_id
            )
            .outerjoin(
                SigmaRule, 
                and_(
                    rule_tactics_map.c.sigma_rule_id == SigmaRule.id,
                    SigmaRule.deleted == False
                )
            )
            .group_by(
                MitreTactic.id,
                MitreTactic.name,
                MitreTactic.tactic_id
            )
            .subquery()
        )
        
        # Final query to order by rule_count
        query = (
            select(
                tactic_count_subquery.c.tactic_name,
                tactic_count_subquery.c.tactic_id,
                tactic_count_subquery.c.rule_count
            )
            .select_from(tactic_count_subquery)
            .order_by(
                desc(tactic_count_subquery.c.rule_count)
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_tactic_coverage_stats(session):
        """
        Get MIN, MAX, AVG coverage per MITRE tactic across all hosts.
        
        Args:
            session: SQLAlchemy session
            
        Returns:
            List of tuples with tactic statistics
        """
        # Get total host count
        host_count_subquery = (
            select(func.count(distinct(Host.id)).label('total_hosts'))
            .select_from(Host)
            .scalar_subquery()
        )
        
        # Create aliases for SigmaRule
        sr_all = aliased(SigmaRule)
        
        # Get tactic statistics using SQLAlchemy
        tactic_stats_subquery = (
            select(
                MitreTactic.name.label('tactic_name'),
                MitreTactic.tactic_id,
                Host.id.label('host_id'),
                Host.hostname,
                func.count(distinct(SigmaRule.id)).label('rules_covered'),
                func.count(distinct(sr_all.id)).label('total_tactic_rules')
            )
            .select_from(MitreTactic)
            .outerjoin(
                rule_tactics_map,
                MitreTactic.id == rule_tactics_map.c.tactic_id
            )
            .outerjoin(
                sr_all,
                and_(
                    rule_tactics_map.c.sigma_rule_id == sr_all.id,
                    sr_all.deleted == False
                )
            )
            .join(
                Host,
                literal(True) == literal(True)  # CROSS JOIN
            )
            .outerjoin(
                HostConfigReview,
                Host.latest_host_config_review_id == HostConfigReview.id
            )
            .outerjoin(
                HostSigmaCompliance,
                and_(
                    HostConfigReview.id == HostSigmaCompliance.host_config_review_id,
                    Host.id == HostSigmaCompliance.host_id
                )
            )
            .outerjoin(
                SigmaRule,
                and_(
                    HostSigmaCompliance.sigma_id == SigmaRule.id,
                    SigmaRule.id == sr_all.id
                )
            )
            .group_by(
                MitreTactic.id,
                MitreTactic.name,
                MitreTactic.tactic_id,
                Host.id,
                Host.hostname
            )
            .having(
                func.count(distinct(sr_all.id)) > 0
            )
            .subquery()
        )
        
        # Final aggregate query
        query = (
            select(
                tactic_stats_subquery.c.tactic_name,
                tactic_stats_subquery.c.tactic_id,
                func.min(
                    func.round(
                        (tactic_stats_subquery.c.rules_covered * 100.0) / 
                        func.nullif(tactic_stats_subquery.c.total_tactic_rules, 0), 
                        2
                    )
                ).label('min_coverage_pct'),
                func.max(
                    func.round(
                        (tactic_stats_subquery.c.rules_covered * 100.0) / 
                        func.nullif(tactic_stats_subquery.c.total_tactic_rules, 0), 
                        2
                    )
                ).label('max_coverage_pct'),
                func.avg(
                    func.round(
                        (tactic_stats_subquery.c.rules_covered * 100.0) / 
                        func.nullif(tactic_stats_subquery.c.total_tactic_rules, 0), 
                        2
                    )
                ).label('avg_coverage_pct'),
                func.round(
                    func.stddev(
                        (tactic_stats_subquery.c.rules_covered * 100.0) / 
                        func.nullif(tactic_stats_subquery.c.total_tactic_rules, 0) 
                    ),
                    2
                ).label('stddev_coverage_pct'),
                func.count(distinct(tactic_stats_subquery.c.host_id)).label('host_count'),
                host_count_subquery.label('total_hosts')
            )
            .select_from(tactic_stats_subquery)
            .group_by(
                tactic_stats_subquery.c.tactic_name,
                tactic_stats_subquery.c.tactic_id
            )
            .order_by(
                desc('avg_coverage_pct')
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_rule_severity_distribution(session):
        """
        Get the distribution of Sigma rules by severity level.
        
        Args:
            session: SQLAlchemy session
            
        Returns:
            List of tuples with severity_level and rule_count
        """
        # Need to use a CTE or subquery to handle the aliased column in GROUP BY and ORDER BY
        severity_subquery = (
            select(
                func.coalesce(SigmaRule.severity, 'undefined').label('severity_level'),
                func.count().label('rule_count')
            )
            .select_from(SigmaRule)
            .where(
                SigmaRule.deleted == False
            )
            .group_by(
                SigmaRule.severity
            )
            .subquery()
        )
        
        # Main query using the subquery
        query = (
            select(
                severity_subquery.c.severity_level,
                severity_subquery.c.rule_count
            )
            .select_from(severity_subquery)
            .order_by(
                case(
                    (severity_subquery.c.severity_level == 'critical', 1),
                    (severity_subquery.c.severity_level == 'high', 2),
                    (severity_subquery.c.severity_level == 'medium', 3),
                    (severity_subquery.c.severity_level == 'low', 4),
                    else_=5
                )
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_technique_coverage_ratio(session):
        """
        Get data for the Rule-to-Technique Coverage Ratio scatter plot.
        
        Args:
            session: SQLAlchemy session
            
        Returns:
            List of tuples with technique coverage data
        """
        # Get technique coverage counts
        technique_coverage_subquery = (
            select(
                MitreTechnique.id.label('technique_id'),
                MitreTechnique.technique_id.label('technique_code'),
                MitreTechnique.name.label('technique_name'),
                func.count(distinct(SigmaRule.id)).label('rule_count')
            )
            .select_from(MitreTechnique)
            .outerjoin(
                rule_techniques_map, 
                MitreTechnique.id == rule_techniques_map.c.technique_id
            )
            .outerjoin(
                SigmaRule, 
                and_(
                    rule_techniques_map.c.sigma_rule_id == SigmaRule.id,
                    SigmaRule.deleted == False
                )
            )
            .group_by(
                MitreTechnique.id,
                MitreTechnique.technique_id,
                MitreTechnique.name
            )
            .subquery('technique_coverage')
        )
        
        # Calculate average rule count for techniques with rules
        avg_rule_count_subquery = (
            select(func.avg(technique_coverage_subquery.c.rule_count))
            .select_from(technique_coverage_subquery)
            .where(technique_coverage_subquery.c.rule_count > 0)
            .scalar_subquery()
        )
        
        # Final query with the coverage ratio calculation
        coverage_ratio = (func.round(
            technique_coverage_subquery.c.rule_count / 
            avg_rule_count_subquery, 
            2
        )).label('coverage_ratio')
        
        query = (
            select(
                technique_coverage_subquery.c.technique_code,
                technique_coverage_subquery.c.technique_name,
                technique_coverage_subquery.c.rule_count,
                avg_rule_count_subquery.label('avg_rule_count'),
                coverage_ratio
            )
            .select_from(technique_coverage_subquery)
            .where(technique_coverage_subquery.c.rule_count > 0)
            .order_by(desc(coverage_ratio))
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_configuration_consistency(session):
        """
        Get data for the Configuration Consistency Analysis heatmap.
        
        Args:
            session: SQLAlchemy session
            
        Returns:
            List of tuples with site, rule, and compliance data
        """
        # Site statistics
        site_stats_subquery = (
            select(
                Host.site,
                SigmaRule.rule_id.label('sigma_rule_id'),
                SigmaRule.name.label('rule_name'),
                func.count(distinct(Host.id)).label('total_hosts_in_site'),
                func.count(distinct(HostSigmaCompliance.host_id)).label('compliant_hosts_in_site')
            )
            .select_from(Host)
            .join(
                SigmaRule,
                SigmaRule.deleted == False,
                isouter=True
            )
            .outerjoin(
                HostConfigReview, 
                Host.latest_host_config_review_id == HostConfigReview.id
            )
            .outerjoin(
                HostSigmaCompliance, 
                and_(
                    HostConfigReview.id == HostSigmaCompliance.host_config_review_id,
                    Host.id == HostSigmaCompliance.host_id,
                    HostSigmaCompliance.sigma_id == SigmaRule.id
                )
            )
            .group_by(
                Host.site,
                SigmaRule.rule_id,
                SigmaRule.name
            )
            .having(
                func.count(distinct(Host.id)) > 0
            )
            .subquery()
        )
        
        # Calculate compliance percentage
        compliance_subquery = (
            select(
                site_stats_subquery.c.site,
                site_stats_subquery.c.sigma_rule_id,
                site_stats_subquery.c.rule_name,
                site_stats_subquery.c.total_hosts_in_site,
                site_stats_subquery.c.compliant_hosts_in_site,
                func.round(
                    (site_stats_subquery.c.compliant_hosts_in_site * 100.0) / 
                    site_stats_subquery.c.total_hosts_in_site, 
                    2
                ).label('compliance_percentage')
            )
            .select_from(site_stats_subquery)
            .subquery()
        )
        
        # Final query to order by site and compliance_percentage
        query = (
            select(
                compliance_subquery.c.site,
                compliance_subquery.c.sigma_rule_id,
                compliance_subquery.c.rule_name,
                compliance_subquery.c.total_hosts_in_site,
                compliance_subquery.c.compliant_hosts_in_site,
                compliance_subquery.c.compliance_percentage
            )
            .select_from(compliance_subquery)
            .order_by(
                compliance_subquery.c.site,
                desc(compliance_subquery.c.compliance_percentage)
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_log_source_coverage(session):
        """
        Get data for the Log Source Category Coverage Analysis treemap.
        
        Args:
            session: SQLAlchemy session
            
        Returns:
            List of tuples with log source and coverage data
        """
        # Build the initial aggregation query
        log_source_subquery = (
            select(
                func.coalesce(SigmaRule.log_source_category, 'Unknown').label('category'),
                func.coalesce(SigmaRule.log_source_service, 'Unknown').label('service'),
                func.coalesce(SigmaRule.log_source_product, 'Unknown').label('product'),
                func.count(distinct(SigmaRule.id)).label('total_rules'),
                func.sum(
                    case(
                        (SigmaRule.enabled == True, 1),
                        else_=0
                    )
                ).label('enabled_rules')
            )
            .select_from(SigmaRule)
            .where(
                SigmaRule.deleted == False
            )
            .group_by(
                SigmaRule.log_source_category,
                SigmaRule.log_source_service,
                SigmaRule.log_source_product
            )
            .subquery()
        )
        
        # Query on the subquery to properly order by the aggregated columns
        query = (
            select(
                log_source_subquery.c.category,
                log_source_subquery.c.service,
                log_source_subquery.c.product,
                log_source_subquery.c.total_rules,
                log_source_subquery.c.enabled_rules
            )
            .select_from(log_source_subquery)
            .order_by(
                desc(log_source_subquery.c.total_rules),
                log_source_subquery.c.category,
                log_source_subquery.c.service,
                log_source_subquery.c.product
            )
        )
        
        result = session.execute(query).all()
        
        # Calculate the enabled percentage for each row
        processed_result = []
        for row in result:
            category, service, product, total_rules, enabled_rules = row
            
            # Calculate enabled percentage, handling division by zero
            if total_rules > 0:
                enabled_percentage = round((enabled_rules * 100.0) / total_rules, 2)
            else:
                enabled_percentage = 0.0
            
            processed_result.append((
                category, 
                service, 
                product, 
                total_rules, 
                enabled_rules, 
                enabled_percentage
            ))
        
        return processed_result
    
    @staticmethod
    def get_host_coverage_percentage_filtered(session, host_ids=None):
        """
        Get the percentage of covered Sigma rules per host, filtered by host IDs.
        
        Args:
            session: SQLAlchemy session
            host_ids: List of host IDs to filter by, or None for all hosts
            
        Returns:
            List of tuples with hostname, ip_address, covered_rules_count, total_rules_count, and coverage_percentage
        """
        # Total non-deleted rules
        total_rules_subquery = (
            select(func.count().label('total_count'))
            .select_from(SigmaRule)
            .where(SigmaRule.deleted == False)
            .scalar_subquery()
        )
        
        # Host coverage query
        host_coverage_query = (
            select(
                Host.id.label('host_id'),
                Host.hostname,
                Host.ip_address,
                func.count(distinct(HostSigmaCompliance.sigma_id)).label('covered_rules_count')
            )
            .select_from(Host)
            .outerjoin(
                HostConfigReview, 
                Host.latest_host_config_review_id == HostConfigReview.id
            )
            .outerjoin(
                HostSigmaCompliance, 
                and_(
                    HostConfigReview.id == HostSigmaCompliance.host_config_review_id,
                    Host.id == HostSigmaCompliance.host_id
                )
            )
        )
        
        # Apply host ID filter if provided
        if host_ids:
            host_coverage_query = host_coverage_query.where(Host.id.in_(host_ids))
        
        # Group by and create subquery
        host_coverage_subquery = (
            host_coverage_query
            .group_by(
                Host.id, 
                Host.hostname, 
                Host.ip_address
            )
            .subquery()
        )
        
        # Final query with coverage percentage calculation
        coverage_query = (
            select(
                host_coverage_subquery.c.hostname,
                host_coverage_subquery.c.ip_address,
                host_coverage_subquery.c.covered_rules_count,
                total_rules_subquery.label('total_rules_count'),
                func.round(
                    (host_coverage_subquery.c.covered_rules_count * 100.0) / 
                    total_rules_subquery, 
                    2
                ).label('coverage_percentage')
            )
            .select_from(host_coverage_subquery)
            .subquery()
        )
        
        # Wrap in another query to be able to order by the calculated percentage
        query = (
            select(
                coverage_query.c.hostname,
                coverage_query.c.ip_address,
                coverage_query.c.covered_rules_count,
                coverage_query.c.total_rules_count,
                coverage_query.c.coverage_percentage
            )
            .select_from(coverage_query)
            .order_by(
                desc(coverage_query.c.coverage_percentage)
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_host_coverage_percentage_potential(session):
        """
        Get the percentage of potential covered Sigma rules per host if all enabled rules were implemented.
        
        Args:
            session: SQLAlchemy session
            
        Returns:
            List of tuples with hostname, ip_address, covered_rules_count, total_rules_count, and coverage_percentage
        """
        # Total enabled non-deleted rules
        total_rules_subquery = (
            select(func.count().label('total_count'))
            .select_from(SigmaRule)
            .where(
                and_(
                    SigmaRule.deleted == False,
                    SigmaRule.enabled == True
                )
            )
            .scalar_subquery()
        )
        
        # Host coverage with all enabled rules
        host_coverage_query = (
            select(
                Host.id.label('host_id'),
                Host.hostname,
                Host.ip_address,
                total_rules_subquery.label('covered_rules_count')
            )
            .select_from(Host)
            .subquery()
        )
        
        # Final query with 100% coverage percentage since all rules are considered covered
        coverage_query = (
            select(
                host_coverage_query.c.hostname,
                host_coverage_query.c.ip_address,
                host_coverage_query.c.covered_rules_count,
                total_rules_subquery.label('total_rules_count'),
                literal(100.0).label('coverage_percentage')
            )
            .select_from(host_coverage_query)
            .subquery()
        )
        
        # Wrap in another query to be able to order hosts alphabetically
        query = (
            select(
                coverage_query.c.hostname,
                coverage_query.c.ip_address,
                coverage_query.c.covered_rules_count,
                coverage_query.c.total_rules_count,
                coverage_query.c.coverage_percentage
            )
            .select_from(coverage_query)
            .order_by(
                coverage_query.c.hostname
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_host_rule_coverage_filtered(session, host_ids=None):
        """
        Get the number of covered Sigma rules per host, filtered by host IDs.
        
        Args:
            session: SQLAlchemy session
            host_ids: List of host IDs to filter by, or None for all hosts
            
        Returns:
            List of tuples with hostname, ip_address, and covered_rules_count
        """
        # Base query
        query = (
            select(
                Host.hostname,
                Host.ip_address,
                func.count(distinct(HostSigmaCompliance.sigma_id)).label('covered_rules_count')
            )
            .select_from(Host)
            .outerjoin(
                HostConfigReview, 
                Host.latest_host_config_review_id == HostConfigReview.id
            )
            .outerjoin(
                HostSigmaCompliance, 
                and_(
                    HostConfigReview.id == HostSigmaCompliance.host_config_review_id,
                    Host.id == HostSigmaCompliance.host_id
                )
            )
        )
        
        # Apply host ID filter if provided
        if host_ids:
            query = query.where(Host.id.in_(host_ids))
        
        # Group by and order by
        query = (
            query
            .group_by(
                Host.hostname, 
                Host.ip_address
            )
            .order_by(
                desc('covered_rules_count'),
                Host.hostname
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_coverage_timeline_filtered(session, host_ids=None):
        """
        Get the coverage timeline data for hosts, filtered by host IDs.
        
        Args:
            session: SQLAlchemy session
            host_ids: List of host IDs to filter by, or None for all hosts
            
        Returns:
            List of tuples with hostname, review_date, covered_rules_count, total_rules_count, and coverage_percentage
        """
        # Total non-deleted rules by date
        total_rules_by_date = (
            select(
                HostConfigReview.created_at.label('review_date'),
                func.count().label('total_count')
            )
            .select_from(SigmaRule)
            .join(
                HostConfigReview,
                and_(
                    SigmaRule.deleted == False,
                    SigmaRule.date <= func.cast(HostConfigReview.created_at, String)
                )
            )
            .group_by(HostConfigReview.created_at)
            .subquery()
        )
        
        # Host coverage timeline query
        timeline_query = (
            select(
                Host.hostname,
                HostConfigReview.created_at.label('review_date'),
                func.count(distinct(HostSigmaCompliance.sigma_id)).label('covered_rules_count'),
                total_rules_by_date.c.total_count.label('total_rules_count'),
                func.round(
                    (func.count(distinct(HostSigmaCompliance.sigma_id)) * 100.0) / 
                    total_rules_by_date.c.total_count, 
                    2
                ).label('coverage_percentage')
            )
            .select_from(HostConfigReview)
            .join(
                Host,
                HostConfigReview.host_id == Host.id
            )
            .join(
                total_rules_by_date,
                HostConfigReview.created_at == total_rules_by_date.c.review_date
            )
            .outerjoin(
                HostSigmaCompliance,
                and_(
                    HostConfigReview.id == HostSigmaCompliance.host_config_review_id,
                    Host.id == HostSigmaCompliance.host_id
                )
            )
        )
        
        # Apply host ID filter if provided
        if host_ids:
            timeline_query = timeline_query.where(Host.id.in_(host_ids))
        
        # Group by and order by
        timeline_query = (
            timeline_query
            .group_by(
                Host.hostname,
                HostConfigReview.created_at,
                total_rules_by_date.c.total_count
            )
            .order_by(
                HostConfigReview.created_at
            )
        )
        
        return session.execute(timeline_query).all()
    
    @staticmethod
    def get_rule_severity_distribution_for_host(session, host_id):
        """
        Get the distribution of rules by severity level for a specific host.
        
        Args:
            session: SQLAlchemy session
            host_id: Host ID to get severity distribution for
            
        Returns:
            List of tuples with severity_level and rule_count
        """
        # Query severity distribution for compliant rules
        query = (
            select(
                SigmaRule.level.label('severity_level'),
                func.count(distinct(SigmaRule.id)).label('rule_count')
            )
            .select_from(Host)
            .join(
                HostConfigReview,
                Host.latest_host_config_review_id == HostConfigReview.id
            )
            .join(
                HostSigmaCompliance,
                and_(
                    HostConfigReview.id == HostSigmaCompliance.host_config_review_id,
                    Host.id == HostSigmaCompliance.host_id
                )
            )
            .join(
                SigmaRule,
                HostSigmaCompliance.sigma_id == SigmaRule.id
            )
            .where(
                Host.id == host_id
            )
            .group_by(
                SigmaRule.level
            )
            .order_by(
                case(
                    (SigmaRule.level == 'critical', 1),
                    (SigmaRule.level == 'high', 2),
                    (SigmaRule.level == 'medium', 3),
                    (SigmaRule.level == 'low', 4),
                    else_=5
                )
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_rule_severity_distribution_for_hosts(session, host_ids):
        """
        Get the distribution of rules by severity level for multiple hosts.
        
        Args:
            session: SQLAlchemy session
            host_ids: List of host IDs to get severity distribution for
            
        Returns:
            List of tuples with severity_level and rule_count
        """
        # Query severity distribution for compliant rules across multiple hosts
        query = (
            select(
                SigmaRule.level.label('severity_level'),
                func.count(distinct(SigmaRule.id)).label('rule_count')
            )
            .select_from(Host)
            .join(
                HostConfigReview,
                Host.latest_host_config_review_id == HostConfigReview.id
            )
            .join(
                HostSigmaCompliance,
                and_(
                    HostConfigReview.id == HostSigmaCompliance.host_config_review_id,
                    Host.id == HostSigmaCompliance.host_id
                )
            )
            .join(
                SigmaRule,
                HostSigmaCompliance.sigma_id == SigmaRule.id
            )
            .where(
                Host.id.in_(host_ids)
            )
            .group_by(
                SigmaRule.level
            )
            .order_by(
                case(
                    (SigmaRule.level == 'critical', 1),
                    (SigmaRule.level == 'high', 2),
                    (SigmaRule.level == 'medium', 3),
                    (SigmaRule.level == 'low', 4),
                    else_=5
                )
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_top_bottom_covered_rules_filtered(session, host_ids=None, limit=10):
        """
        Get the top and bottom covered rules by host count, filtered by host IDs.
        
        Args:
            session: SQLAlchemy session
            host_ids: List of host IDs to filter by, or None for all hosts
            limit: Number of top and bottom rules to return
            
        Returns:
            List of tuples with rule_name, sigma_rule_id, compliant_hosts_count, and category
        """
        # Create base query for rule coverage counts
        base_query = (
            select(
                SigmaRule.id.label('sigma_rule_id'),
                SigmaRule.rule_id,
                SigmaRule.name.label('rule_name'),
                func.count(distinct(Host.id)).label('compliant_hosts_count')
            )
            .select_from(SigmaRule)
            .join(
                HostSigmaCompliance,
                SigmaRule.id == HostSigmaCompliance.sigma_id
            )
            .join(
                HostConfigReview,
                HostSigmaCompliance.host_config_review_id == HostConfigReview.id
            )
            .join(
                Host,
                and_(
                    Host.id == HostSigmaCompliance.host_id,
                    Host.latest_host_config_review_id == HostConfigReview.id
                )
            )
        )
        
        # Apply host ID filter if provided
        if host_ids:
            base_query = base_query.where(Host.id.in_(host_ids))
        
        # Group by and create subquery
        coverage_subquery = (
            base_query
            .where(
                or_(SigmaRule.deleted == False, SigmaRule.deleted == None)
            )
            .group_by(
                SigmaRule.id,
                SigmaRule.rule_id,
                SigmaRule.name
            )
            .subquery()
        )
        
        # Get total number of hosts
        total_hosts_query = (
            select(func.count(distinct(Host.id)))
            .select_from(Host)
        )
        
        # Apply host ID filter if provided
        if host_ids:
            total_hosts_query = total_hosts_query.where(Host.id.in_(host_ids))
            
        total_hosts = session.execute(total_hosts_query).scalar()
        
        # Query for top covered rules (most compliant hosts)
        top_query = (
            select(
                coverage_subquery.c.rule_name,
                coverage_subquery.c.rule_id.label('sigma_rule_id'),
                coverage_subquery.c.compliant_hosts_count,
                literal('Top Covered').label('category')
            )
            .select_from(coverage_subquery)
            .order_by(
                desc(coverage_subquery.c.compliant_hosts_count)
            )
            .limit(limit)
        )
        
        # Query for bottom covered rules (least compliant hosts)
        bottom_query = (
            select(
                coverage_subquery.c.rule_name,
                coverage_subquery.c.rule_id.label('sigma_rule_id'),
                coverage_subquery.c.compliant_hosts_count,
                literal('Bottom Covered').label('category')
            )
            .select_from(coverage_subquery)
            .where(coverage_subquery.c.compliant_hosts_count > 0)  # At least one compliant host
            .order_by(
                coverage_subquery.c.compliant_hosts_count
            )
            .limit(limit)
        )
        
        # Union all to combine top and bottom
        union_query = union_all(top_query, bottom_query)
        
        # Wrap in a final query to order by category and count
        final_query = (
            select(
                union_query.c.rule_name,
                union_query.c.sigma_rule_id,
                union_query.c.compliant_hosts_count,
                union_query.c.category
            )
            .select_from(union_query)
            .order_by(
                case((union_query.c.category == 'Top Covered', 0), else_=1),
                desc(union_query.c.compliant_hosts_count)
            )
        )
        
        return session.execute(final_query).all()
    
    @staticmethod
    def get_mitre_tactic_distribution_for_host(session, host_id):
        """
        Get the distribution of MITRE ATT&CK tactics for a specific host's rules.
        
        Args:
            session: SQLAlchemy session
            host_id: Host ID to get tactic distribution for
            
        Returns:
            List of tuples with tactic_name, tactic_id, and rule_count
        """
        # Query tactic distribution for compliant rules
        query = (
            select(
                MitreTactic.name.label('tactic_name'),
                MitreTactic.tactic_id,
                func.count(distinct(SigmaRule.id)).label('rule_count')
            )
            .select_from(Host)
            .join(
                HostConfigReview,
                Host.latest_host_config_review_id == HostConfigReview.id
            )
            .join(
                HostSigmaCompliance,
                and_(
                    HostConfigReview.id == HostSigmaCompliance.host_config_review_id,
                    Host.id == HostSigmaCompliance.host_id
                )
            )
            .join(
                SigmaRule,
                HostSigmaCompliance.sigma_id == SigmaRule.id
            )
            .join(
                rule_tactics_map,
                SigmaRule.id == rule_tactics_map.c.sigma_rule_id
            )
            .join(
                MitreTactic,
                rule_tactics_map.c.tactic_id == MitreTactic.id
            )
            .where(
                Host.id == host_id
            )
            .group_by(
                MitreTactic.name,
                MitreTactic.tactic_id
            )
            .order_by(
                desc('rule_count')
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_mitre_tactic_distribution_for_hosts(session, host_ids):
        """
        Get the distribution of MITRE ATT&CK tactics for multiple hosts' rules.
        
        Args:
            session: SQLAlchemy session
            host_ids: List of host IDs to get tactic distribution for
            
        Returns:
            List of tuples with tactic_name, tactic_id, and rule_count
        """
        # Query tactic distribution for compliant rules across multiple hosts
        query = (
            select(
                MitreTactic.name.label('tactic_name'),
                MitreTactic.tactic_id,
                func.count(distinct(SigmaRule.id)).label('rule_count')
            )
            .select_from(Host)
            .join(
                HostConfigReview,
                Host.latest_host_config_review_id == HostConfigReview.id
            )
            .join(
                HostSigmaCompliance,
                and_(
                    HostConfigReview.id == HostSigmaCompliance.host_config_review_id,
                    Host.id == HostSigmaCompliance.host_id
                )
            )
            .join(
                SigmaRule,
                HostSigmaCompliance.sigma_id == SigmaRule.id
            )
            .join(
                rule_tactics_map,
                SigmaRule.id == rule_tactics_map.c.sigma_rule_id
            )
            .join(
                MitreTactic,
                rule_tactics_map.c.tactic_id == MitreTactic.id
            )
            .where(
                Host.id.in_(host_ids)
            )
            .group_by(
                MitreTactic.name,
                MitreTactic.tactic_id
            )
            .order_by(
                desc('rule_count')
            )
        )
        
        return session.execute(query).all()
        
    @staticmethod
    def get_technique_coverage_ratio_for_host(session, host_id):
        """
        Get the technique coverage ratio for a specific host.
        
        Args:
            session: SQLAlchemy session
            host_id: Host ID to get technique coverage for
            
        Returns:
            List of tuples with technique_code, technique_name, rule_count, avg_rule_count, and coverage_ratio
        """
        # First, get a count of rules per technique across all rules
        all_rules_per_technique = (
            select(
                MitreTechnique.id.label('technique_id'),
                func.count(distinct(SigmaRule.id)).label('rule_count')
            )
            .select_from(MitreTechnique)
            .join(
                rule_techniques_map,
                MitreTechnique.id == rule_techniques_map.c.technique_id
            )
            .join(
                SigmaRule,
                and_(
                    rule_techniques_map.c.sigma_rule_id == SigmaRule.id,
                    SigmaRule.deleted == False
                )
            )
            .group_by(MitreTechnique.id)
            .subquery()
        )
        
        # Calculate the average rules per technique as a scalar value
        avg_rules_per_technique = (
            select(func.avg(all_rules_per_technique.c.rule_count))
            .select_from(all_rules_per_technique)
            .scalar_subquery()
        )
        
        # Now get rule count per technique for the specific host
        host_technique_rule_count = (
            select(
                MitreTechnique.id.label('technique_id'),
                func.count(distinct(SigmaRule.id)).label('rule_count')
            )
            .select_from(Host)
            .join(
                HostConfigReview,
                Host.latest_host_config_review_id == HostConfigReview.id
            )
            .join(
                HostSigmaCompliance,
                and_(
                    HostConfigReview.id == HostSigmaCompliance.host_config_review_id,
                    Host.id == HostSigmaCompliance.host_id
                )
            )
            .join(
                SigmaRule,
                HostSigmaCompliance.sigma_id == SigmaRule.id
            )
            .join(
                rule_techniques_map,
                SigmaRule.id == rule_techniques_map.c.sigma_rule_id
            )
            .join(
                MitreTechnique,
                rule_techniques_map.c.technique_id == MitreTechnique.id
            )
            .where(
                Host.id == host_id
            )
            .group_by(
                MitreTechnique.id
            )
            .subquery()
        )
        
        # Final query to join and calculate the coverage ratio
        query = (
            select(
                MitreTechnique.technique_id.label('technique_code'),
                MitreTechnique.name.label('technique_name'),
                host_technique_rule_count.c.rule_count,
                avg_rules_per_technique.label('avg_rule_count'),
                (host_technique_rule_count.c.rule_count / func.cast(avg_rules_per_technique, Float)).label('coverage_ratio')
            )
            .select_from(MitreTechnique)
            .join(
                host_technique_rule_count,
                MitreTechnique.id == host_technique_rule_count.c.technique_id
            )
            .order_by(
                desc('coverage_ratio')
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_technique_coverage_ratio_for_hosts(session, host_ids):
        """
        Get the technique coverage ratio for multiple hosts.
        
        Args:
            session: SQLAlchemy session
            host_ids: List of host IDs to get technique coverage for
            
        Returns:
            List of tuples with technique_code, technique_name, rule_count, avg_rule_count, and coverage_ratio
        """
        # First, get a count of rules per technique across all rules
        all_rules_per_technique = (
            select(
                MitreTechnique.id.label('technique_id'),
                func.count(distinct(SigmaRule.id)).label('rule_count')
            )
            .select_from(MitreTechnique)
            .join(
                rule_techniques_map,
                MitreTechnique.id == rule_techniques_map.c.technique_id
            )
            .join(
                SigmaRule,
                and_(
                    rule_techniques_map.c.sigma_rule_id == SigmaRule.id,
                    SigmaRule.deleted == False
                )
            )
            .group_by(MitreTechnique.id)
            .subquery()
        )
        
        # Calculate the average rules per technique as a scalar value
        avg_rules_per_technique = (
            select(func.avg(all_rules_per_technique.c.rule_count))
            .select_from(all_rules_per_technique)
            .scalar_subquery()
        )
        
        # Now get rule count per technique for the filtered hosts
        host_technique_rule_count = (
            select(
                MitreTechnique.id.label('technique_id'),
                func.count(distinct(SigmaRule.id)).label('rule_count')
            )
            .select_from(Host)
            .join(
                HostConfigReview,
                Host.latest_host_config_review_id == HostConfigReview.id
            )
            .join(
                HostSigmaCompliance,
                and_(
                    HostConfigReview.id == HostSigmaCompliance.host_config_review_id,
                    Host.id == HostSigmaCompliance.host_id
                )
            )
            .join(
                SigmaRule,
                HostSigmaCompliance.sigma_id == SigmaRule.id
            )
            .join(
                rule_techniques_map,
                SigmaRule.id == rule_techniques_map.c.sigma_rule_id
            )
            .join(
                MitreTechnique,
                rule_techniques_map.c.technique_id == MitreTechnique.id
            )
            .where(
                Host.id.in_(host_ids)
            )
            .group_by(
                MitreTechnique.id
            )
            .subquery()
        )
        
        # Final query to join and calculate the coverage ratio
        query = (
            select(
                MitreTechnique.technique_id.label('technique_code'),
                MitreTechnique.name.label('technique_name'),
                host_technique_rule_count.c.rule_count,
                avg_rules_per_technique.label('avg_rule_count'),
                (host_technique_rule_count.c.rule_count / func.cast(avg_rules_per_technique, Float)).label('coverage_ratio')
            )
            .select_from(MitreTechnique)
            .join(
                host_technique_rule_count,
                MitreTechnique.id == host_technique_rule_count.c.technique_id
            )
            .order_by(
                desc('coverage_ratio')
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_tactic_coverage_stats_filtered(session, host_ids=None):
        """
        Get MITRE ATT&CK tactic coverage statistics filtered by host IDs.
        
        Args:
            session: SQLAlchemy session
            host_ids: List of host IDs to filter by, or None for all hosts
            
        Returns:
            List of tuples with tactic_name, tactic_id, min_coverage_pct, max_coverage_pct, 
            avg_coverage_pct, stddev_coverage_pct, host_count, and total_hosts
        """
        # Get tactics for which we have rules
        tactics_with_rules = (
            select(
                MitreTactic.id,
                MitreTactic.tactic_id,
                MitreTactic.name
            )
            .select_from(MitreTactic)
            .join(
                rule_tactics_map,
                MitreTactic.id == rule_tactics_map.c.tactic_id
            )
            .join(
                SigmaRule,
                rule_tactics_map.c.sigma_rule_id == SigmaRule.id
            )
            .where(
                SigmaRule.deleted == False
            )
            .group_by(
                MitreTactic.id,
                MitreTactic.tactic_id,
                MitreTactic.name
            )
            .order_by(
                MitreTactic.name
            )
            .subquery()
        )
        
        # Total rule count per tactic
        total_rules_per_tactic = (
            select(
                tactics_with_rules.c.id.label('tactic_id'),
                func.count(distinct(SigmaRule.id)).label('total_rules')
            )
            .select_from(tactics_with_rules)
            .join(
                rule_tactics_map,
                tactics_with_rules.c.id == rule_tactics_map.c.tactic_id
            )
            .join(
                SigmaRule,
                rule_tactics_map.c.sigma_rule_id == SigmaRule.id
            )
            .where(
                SigmaRule.deleted == False
            )
            .group_by(
                tactics_with_rules.c.id
            )
            .subquery()
        )
        
        # Base query for host coverage per tactic
        host_tactic_coverage_base = (
            select(
                Host.id.label('host_id'),
                Host.hostname,
                tactics_with_rules.c.id.label('tactic_id'),
                tactics_with_rules.c.name.label('tactic_name'),
                tactics_with_rules.c.tactic_id.label('tactic_code'),
                func.count(distinct(SigmaRule.id)).label('covered_rules'),
                total_rules_per_tactic.c.total_rules,
                (func.count(distinct(SigmaRule.id)) * 100.0 / total_rules_per_tactic.c.total_rules).label('coverage_pct')
            )
            .select_from(Host)
            .join(
                HostConfigReview, 
                Host.latest_host_config_review_id == HostConfigReview.id
            )
            .join(
                HostSigmaCompliance, 
                and_(
                    HostConfigReview.id == HostSigmaCompliance.host_config_review_id,
                    Host.id == HostSigmaCompliance.host_id
                )
            )
            .join(
                SigmaRule,
                HostSigmaCompliance.sigma_id == SigmaRule.id
            )
            .join(
                rule_tactics_map,
                SigmaRule.id == rule_tactics_map.c.sigma_rule_id
            )
            .join(
                tactics_with_rules,
                rule_tactics_map.c.tactic_id == tactics_with_rules.c.id
            )
            .join(
                total_rules_per_tactic,
                tactics_with_rules.c.id == total_rules_per_tactic.c.tactic_id
            )
        )
        
        # Apply host ID filter if provided
        if host_ids:
            host_tactic_coverage_base = host_tactic_coverage_base.where(Host.id.in_(host_ids))
        
        # Group by and create subquery
        host_tactic_coverage = (
            host_tactic_coverage_base
            .group_by(
                Host.id,
                Host.hostname,
                tactics_with_rules.c.id,
                tactics_with_rules.c.name,
                tactics_with_rules.c.tactic_id,
                total_rules_per_tactic.c.total_rules
            )
            .subquery()
        )
        
        # Get total number of hosts
        total_hosts_query = (
            select(func.count(distinct(Host.id)))
            .select_from(Host)
        )
        
        # Apply host ID filter if provided
        if host_ids:
            total_hosts_query = total_hosts_query.where(Host.id.in_(host_ids))
            
        total_hosts = session.execute(total_hosts_query).scalar()
        
        # Final query for tactic statistics
        tactic_stats_query = (
            select(
                host_tactic_coverage.c.tactic_name,
                host_tactic_coverage.c.tactic_code.label('tactic_id'),
                func.min(host_tactic_coverage.c.coverage_pct).label('min_coverage_pct'),
                func.max(host_tactic_coverage.c.coverage_pct).label('max_coverage_pct'),
                func.avg(host_tactic_coverage.c.coverage_pct).label('avg_coverage_pct'),
                func.stddev(host_tactic_coverage.c.coverage_pct).label('stddev_coverage_pct'),
                func.count(distinct(host_tactic_coverage.c.host_id)).label('host_count'),
                literal(total_hosts).label('total_hosts')
            )
            .select_from(host_tactic_coverage)
            .group_by(
                host_tactic_coverage.c.tactic_name,
                host_tactic_coverage.c.tactic_code
            )
            .order_by(
                host_tactic_coverage.c.tactic_name
            )
        )
        
        return session.execute(tactic_stats_query).all()
    
    @staticmethod
    def get_configuration_consistency_filtered(session, host_ids=None):
        """
        Get site-based configuration consistency analysis, filtered by host IDs.
        
        Args:
            session: SQLAlchemy session
            host_ids: List of host IDs to filter by, or None for all hosts
            
        Returns:
            List of tuples with site, sigma_rule_id, rule_name, total_hosts_in_site, 
            compliant_hosts_in_site, and compliance_percentage
        """
        # Base query to get the total number of hosts per site
        total_hosts_per_site_base = (
            select(
                Host.site,
                func.count(distinct(Host.id)).label('total_hosts')
            )
            .select_from(Host)
            .where(Host.site != None)
        )
        
        # Apply host ID filter if provided
        if host_ids:
            total_hosts_per_site_base = total_hosts_per_site_base.where(Host.id.in_(host_ids))
        
        # Group by site and create subquery
        total_hosts_per_site = (
            total_hosts_per_site_base
            .group_by(Host.site)
            .subquery()
        )
        
        # Base query to get compliant hosts per site and rule
        compliant_hosts_per_site_rule_base = (
            select(
                Host.site,
                SigmaRule.rule_id.label('sigma_rule_id'),
                SigmaRule.name.label('rule_name'),
                func.count(distinct(Host.id)).label('compliant_hosts')
            )
            .select_from(Host)
            .join(
                HostConfigReview, 
                Host.latest_host_config_review_id == HostConfigReview.id
            )
            .join(
                HostSigmaCompliance, 
                and_(
                    HostConfigReview.id == HostSigmaCompliance.host_config_review_id,
                    Host.id == HostSigmaCompliance.host_id
                )
            )
            .join(
                SigmaRule,
                HostSigmaCompliance.sigma_id == SigmaRule.id
            )
            .where(
                and_(
                    Host.site != None,
                    SigmaRule.deleted == False
                )
            )
        )
        
        # Apply host ID filter if provided
        if host_ids:
            compliant_hosts_per_site_rule_base = compliant_hosts_per_site_rule_base.where(Host.id.in_(host_ids))
        
        # Group by site, rule_id, and rule_name and create subquery
        compliant_hosts_per_site_rule = (
            compliant_hosts_per_site_rule_base
            .group_by(
                Host.site,
                SigmaRule.rule_id,
                SigmaRule.name
            )
            .subquery()
        )
        
        # Final query to join and calculate compliance percentage
        consistency_query = (
            select(
                compliant_hosts_per_site_rule.c.site,
                compliant_hosts_per_site_rule.c.sigma_rule_id,
                compliant_hosts_per_site_rule.c.rule_name,
                total_hosts_per_site.c.total_hosts.label('total_hosts_in_site'),
                compliant_hosts_per_site_rule.c.compliant_hosts.label('compliant_hosts_in_site'),
                (compliant_hosts_per_site_rule.c.compliant_hosts * 100.0 / 
                 total_hosts_per_site.c.total_hosts).label('compliance_percentage')
            )
            .select_from(compliant_hosts_per_site_rule)
            .join(
                total_hosts_per_site,
                compliant_hosts_per_site_rule.c.site == total_hosts_per_site.c.site
            )
            .order_by(
                compliant_hosts_per_site_rule.c.site,
                desc('compliance_percentage')
            )
        )
        
        return session.execute(consistency_query).all() 
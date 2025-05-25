from sqlalchemy import func, case, select, and_, or_, not_, distinct, desc, text, over, literal, union_all, Table
from sqlalchemy.orm import aliased
from sqlalchemy.sql import functions
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
    HostConfigReviewEntry,
    NetBoxTag,
    tag_device_rule_map as TagDeviceRule
)


class AdditionalHostCoverage:
    """
    Class providing methods to query additional host coverage data from the database using SQLAlchemy.
    """
    
    @staticmethod
    def get_outlier_analysis(session):
        """
        Identify outliers in host coverage within each site using z-scores.
        
        Args:
            session: SQLAlchemy session
            
        Returns:
            List of tuples with hostname, site, platform_os, covered_rules, avg_coverage, 
            stddev_coverage, z_score, and performance_category
        """
        # Host coverage subquery
        host_coverage_subquery = (
            select(
                Host.id.label('host_id'),
                Host.hostname,
                Host.site,
                Host.platform_os,
                func.count(distinct(HostSigmaCompliance.sigma_id)).label('covered_rules')
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
                Host.site, 
                Host.platform_os
            )
            .subquery()
        )
        
        # Site statistics subquery
        site_stats_subquery = (
            select(
                host_coverage_subquery.c.site,
                func.avg(host_coverage_subquery.c.covered_rules).label('avg_coverage'),
                func.stddev(host_coverage_subquery.c.covered_rules).label('stddev_coverage')
            )
            .select_from(host_coverage_subquery)
            .where(host_coverage_subquery.c.site != None)
            .group_by(host_coverage_subquery.c.site)
            .subquery()
        )
        
        # Calculate z-score and performance category
        z_score = ((host_coverage_subquery.c.covered_rules - site_stats_subquery.c.avg_coverage) / 
                   func.nullif(site_stats_subquery.c.stddev_coverage, 0)).label('z_score')
        
        # Define performance category based on z-score
        performance_category = case(
            (z_score < -1, 'Severely Below Average'),
            (z_score < -0.3, 'Below Average'),
            (z_score > 1, 'Exceptionally Above Average'),
            (z_score > 0.3, 'Above Average'),
            else_='Average'
        ).label('performance_category')
        
        # Final query
        query = (
            select(
                host_coverage_subquery.c.hostname,
                host_coverage_subquery.c.site,
                host_coverage_subquery.c.platform_os,
                host_coverage_subquery.c.covered_rules,
                site_stats_subquery.c.avg_coverage,
                site_stats_subquery.c.stddev_coverage,
                z_score,
                performance_category
            )
            .select_from(host_coverage_subquery)
            .join(
                site_stats_subquery, 
                host_coverage_subquery.c.site == site_stats_subquery.c.site
            )
            .where(site_stats_subquery.c.stddev_coverage > 0)
            .order_by(
                func.abs(z_score).desc()
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_host_coverage_by_tag(session):
        """
        Get the average Sigma rule coverage percentage by host tag.
        
        Args:
            session: SQLAlchemy session
            
        Returns:
            List of tuples with tag_name, hosts_count, and avg_coverage_percentage
        """
        # Get total enabled rules count
        total_rules_subquery = (
            select(func.count())
            .select_from(SigmaRule)
            .where(
                and_(
                    SigmaRule.enabled == True,
                    SigmaRule.deleted == False
                )
            )
            .scalar_subquery()
        )
        
        # Main query
        query = (
            select(
                NetBoxTag.name.label('tag_name'),
                func.count(distinct(Host.id)).label('hosts_count'),
                over(
                    func.avg(
                        func.count(distinct(HostSigmaCompliance.sigma_id)) * 100.0 / 
                        total_rules_subquery
                    ),
                    partition_by=NetBoxTag.id
                ).label('avg_coverage_percentage')
            )
            .select_from(NetBoxTag)
            .join(
                TagDeviceRule, 
                NetBoxTag.id == TagDeviceRule.c.tag_id
            )
            .join(
                Host, 
                TagDeviceRule.c.device_id == Host.id
            )
            .outerjoin(
                HostConfigReview, 
                Host.latest_host_config_review_id == HostConfigReview.id
            )
            .outerjoin(
                HostSigmaCompliance, 
                HostConfigReview.id == HostSigmaCompliance.host_config_review_id
            )
            .group_by(
                NetBoxTag.id, 
                NetBoxTag.name, 
                Host.id
            )
            .order_by(
                desc('avg_coverage_percentage')
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_host_coverage_by_platform(session):
        """
        Get the average, minimum, and maximum Sigma rule coverage percentage by platform OS.
        
        Args:
            session: SQLAlchemy session
            
        Returns:
            List of tuples with platform_os, host_count, avg_coverage_percentage,
            min_coverage_percentage, max_coverage_percentage, and stddev_coverage_percentage
        """
        # Get total enabled rules count
        total_rules_subquery = (
            select(func.count())
            .select_from(SigmaRule)
            .where(
                and_(
                    SigmaRule.enabled == True,
                    SigmaRule.deleted == False
                )
            )
            .scalar_subquery()
        )
        
        # Coverage percentage subquery
        coverage_subquery = (
            select(
                Host.id,
                (func.count(distinct(HostSigmaCompliance.sigma_id)) * 100.0 / 
                 total_rules_subquery).label('coverage_percentage')
            )
            .select_from(Host)
            .outerjoin(
                HostConfigReview, 
                Host.latest_host_config_review_id == HostConfigReview.id
            )
            .outerjoin(
                HostSigmaCompliance, 
                HostConfigReview.id == HostSigmaCompliance.host_config_review_id
            )
            .group_by(Host.id)
            .subquery()
        )
        
        # Main query
        query = (
            select(
                Host.platform_os,
                func.count(distinct(Host.id)).label('host_count'),
                func.avg(coverage_subquery.c.coverage_percentage).label('avg_coverage_percentage'),
                func.min(coverage_subquery.c.coverage_percentage).label('min_coverage_percentage'),
                func.max(coverage_subquery.c.coverage_percentage).label('max_coverage_percentage'),
                func.stddev(coverage_subquery.c.coverage_percentage).label('stddev_coverage_percentage')
            )
            .select_from(Host)
            .join(
                coverage_subquery,
                Host.id == coverage_subquery.c.id
            )
            .where(Host.platform_os != None)
            .group_by(Host.platform_os)
            .order_by(desc('avg_coverage_percentage'))
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_host_vulnerability_exposure(session, limit=10):
        """
        Get hosts with missing critical or high severity rules.
        
        Args:
            session: SQLAlchemy session
            limit: Maximum number of hosts to return (default: 10)
            
        Returns:
            List of tuples with hostname, ip_address, missing_critical_rules, and critical_rules_missing
        """
        # First, get all critical/high severity rules
        critical_rules_subquery = (
            select(
                SigmaRule.id,
                SigmaRule.name
            )
            .select_from(SigmaRule)
            .where(
                and_(
                    SigmaRule.level.in_(['critical', 'high']),
                    SigmaRule.enabled == True,
                    SigmaRule.deleted == False
                )
            )
            .subquery()
        )
        
        # Then, for each host, find which critical rules they're missing
        host_compliance_subquery = (
            select(
                Host.id.label('host_id'),
                HostSigmaCompliance.sigma_id
            )
            .select_from(Host)
            .outerjoin(
                HostConfigReview, 
                Host.latest_host_config_review_id == HostConfigReview.id
            )
            .outerjoin(
                HostSigmaCompliance, 
                HostConfigReview.id == HostSigmaCompliance.host_config_review_id
            )
            .subquery()
        )
        
        # Get missing rules for each host
        missing_rules_query = (
            select(
                Host.id,
                Host.hostname,
                Host.ip_address,
                critical_rules_subquery.c.id.label('rule_id'),
                critical_rules_subquery.c.name.label('rule_name')
            )
            .select_from(Host)
            .join(
                critical_rules_subquery,
                literal(True) == literal(True)  # Cross join all critical rules with all hosts
            )
            .outerjoin(
                host_compliance_subquery,
                and_(
                    Host.id == host_compliance_subquery.c.host_id,
                    critical_rules_subquery.c.id == host_compliance_subquery.c.sigma_id
                )
            )
            .where(host_compliance_subquery.c.sigma_id == None)  # Only include rules that are not covered
            .subquery()
        )
        
        # Final aggregation query
        query = (
            select(
                Host.hostname,
                Host.ip_address,
                func.count(distinct(missing_rules_query.c.rule_id)).label('missing_critical_rules'),
                func.string_agg(missing_rules_query.c.rule_name, text("', '")).label('critical_rules_missing')
            )
            .select_from(Host)
            .join(
                missing_rules_query,
                Host.id == missing_rules_query.c.id
            )
            .group_by(
                Host.id,
                Host.hostname,
                Host.ip_address
            )
            .having(
                func.count(distinct(missing_rules_query.c.rule_id)) > 0
            )
            .order_by(
                desc('missing_critical_rules')
            )
            .limit(limit)
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_host_coverage_by_severity_level(session):
        """
        Get Sigma rule coverage percentage by severity level for each host.
        
        Args:
            session: SQLAlchemy session
            
        Returns:
            List of tuples with hostname, site, level, covered_rules_count, 
            total_rules_by_level, and coverage_percentage
        """
        # Using a window function to calculate total rules by level
        total_rules_by_level_subquery = (
            select(
                SigmaRule.level,
                func.count().label('total_rules')
            )
            .select_from(SigmaRule)
            .where(
                and_(
                    SigmaRule.enabled == True,
                    SigmaRule.deleted == False
                )
            )
            .group_by(SigmaRule.level)
            .subquery()
        )
        
        # Main query
        query = (
            select(
                Host.hostname,
                Host.site,
                SigmaRule.level,
                func.count(distinct(HostSigmaCompliance.sigma_id)).label('covered_rules_count'),
                total_rules_by_level_subquery.c.total_rules.label('total_rules_by_level'),
                (func.count(distinct(HostSigmaCompliance.sigma_id)) * 100.0 / 
                 func.nullif(total_rules_by_level_subquery.c.total_rules, 0)).label('coverage_percentage')
            )
            .select_from(Host)
            .join(
                HostConfigReview, 
                Host.latest_host_config_review_id == HostConfigReview.id
            )
            .join(
                HostSigmaCompliance, 
                HostConfigReview.id == HostSigmaCompliance.host_config_review_id
            )
            .join(
                SigmaRule, 
                HostSigmaCompliance.sigma_id == SigmaRule.id
            )
            .join(
                total_rules_by_level_subquery,
                SigmaRule.level == total_rules_by_level_subquery.c.level
            )
            .group_by(
                Host.hostname, 
                Host.site, 
                SigmaRule.level,
                total_rules_by_level_subquery.c.total_rules
            )
            .order_by(
                Host.hostname, 
                SigmaRule.level
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_gap_analysis(session):
        """
        Get the gap analysis showing missing rules count and gap percentage for each host.
        
        Args:
            session: SQLAlchemy session
            
        Returns:
            List of tuples with hostname, ip_address, platform_os, missing_rules_count, and gap_percentage
        """
        # Get total enabled rules count
        total_rules_subquery = (
            select(func.count())
            .select_from(SigmaRule)
            .where(
                and_(
                    SigmaRule.enabled == True,
                    SigmaRule.deleted == False
                )
            )
            .scalar_subquery()
        )
        
        # Main query
        query = (
            select(
                Host.hostname,
                Host.ip_address,
                Host.platform_os,
                (total_rules_subquery - func.count(distinct(HostSigmaCompliance.sigma_id))).label('missing_rules_count'),
                (100 - (func.count(distinct(HostSigmaCompliance.sigma_id)) * 100.0 / 
                        total_rules_subquery)).label('gap_percentage')
            )
            .select_from(Host)
            .outerjoin(
                HostConfigReview, 
                Host.latest_host_config_review_id == HostConfigReview.id
            )
            .outerjoin(
                HostSigmaCompliance, 
                HostConfigReview.id == HostSigmaCompliance.host_config_review_id
            )
            .group_by(
                Host.id, 
                Host.hostname, 
                Host.ip_address, 
                Host.platform_os,
                total_rules_subquery
            )
            .order_by(
                desc('gap_percentage')
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_host_coverage_by_platform_filtered(session, host_ids=None):
        """
        Get the average, minimum, and maximum Sigma rule coverage percentage by platform OS,
        filtered by host IDs.
        
        Args:
            session: SQLAlchemy session
            host_ids: List of host IDs to filter by
            
        Returns:
            List of tuples with platform_os, host_count, avg_coverage_percentage,
            min_coverage_percentage, max_coverage_percentage, and stddev_coverage_percentage
        """
        # Get total enabled rules count
        total_rules_subquery = (
            select(func.count().label('total_count'))
            .select_from(SigmaRule)
            .where(
                and_(
                    SigmaRule.enabled == True,
                    SigmaRule.deleted == False
                )
            )
            .scalar_subquery()
        )
        
        # Base host coverage query
        host_coverage_query = (
            select(
                Host.platform_os,
                Host.id.label('host_id'),
                func.count(distinct(HostSigmaCompliance.sigma_id)).label('covered_rules_count'),
                (func.count(distinct(HostSigmaCompliance.sigma_id)) * 100.0 / 
                 total_rules_subquery).label('coverage_percentage')
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
            .where(Host.platform_os != None)
        )
        
        # Apply host ID filter if provided
        if host_ids:
            host_coverage_query = host_coverage_query.where(Host.id.in_(host_ids))
        
        # Group by and create subquery
        host_coverage_subquery = (
            host_coverage_query
            .group_by(
                Host.platform_os,
                Host.id
            )
            .subquery()
        )
        
        # Final query for platform statistics
        platform_stats_query = (
            select(
                host_coverage_subquery.c.platform_os,
                func.count(distinct(host_coverage_subquery.c.host_id)).label('host_count'),
                func.avg(host_coverage_subquery.c.coverage_percentage).label('avg_coverage_percentage'),
                func.min(host_coverage_subquery.c.coverage_percentage).label('min_coverage_percentage'),
                func.max(host_coverage_subquery.c.coverage_percentage).label('max_coverage_percentage'),
                func.stddev(host_coverage_subquery.c.coverage_percentage).label('stddev_coverage_percentage')
            )
            .select_from(host_coverage_subquery)
            .group_by(
                host_coverage_subquery.c.platform_os
            )
            .order_by(
                desc('avg_coverage_percentage')
            )
        )
        
        return session.execute(platform_stats_query).all()
    
    @staticmethod
    def get_host_coverage_by_tag_filtered(session, host_ids=None):
        """
        Get the average Sigma rule coverage percentage by host tag,
        filtered by host IDs.
        
        Args:
            session: SQLAlchemy session
            host_ids: List of host IDs to filter by
            
        Returns:
            List of tuples with tag_name, hosts_count, and avg_coverage_percentage
        """
        # Get total enabled rules count
        total_rules_subquery = (
            select(func.count())
            .select_from(SigmaRule)
            .where(
                and_(
                    SigmaRule.enabled == True,
                    SigmaRule.deleted == False
                )
            )
            .scalar_subquery()
        )
        
        # Base query
        host_tag_coverage_query = (
            select(
                NetBoxTag.name.label('tag_name'),
                NetBoxTag.id.label('tag_id'),
                Host.id.label('host_id'),
                func.count(distinct(HostSigmaCompliance.sigma_id)).label('covered_rules_count'),
                (func.count(distinct(HostSigmaCompliance.sigma_id)) * 100.0 / 
                 total_rules_subquery).label('coverage_percentage')
            )
            .select_from(NetBoxTag)
            .join(
                TagDeviceRule, 
                NetBoxTag.id == TagDeviceRule.c.tag_id
            )
            .join(
                Host, 
                TagDeviceRule.c.device_id == Host.id
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
        )
        
        # Apply host ID filter if provided
        if host_ids:
            host_tag_coverage_query = host_tag_coverage_query.where(Host.id.in_(host_ids))
        
        # Group by and create subquery
        host_tag_coverage_subquery = (
            host_tag_coverage_query
            .group_by(
                NetBoxTag.name,
                NetBoxTag.id,
                Host.id
            )
            .subquery()
        )
        
        # Final query for tag statistics
        tag_stats_query = (
            select(
                host_tag_coverage_subquery.c.tag_name,
                func.count(distinct(host_tag_coverage_subquery.c.host_id)).label('hosts_count'),
                func.avg(host_tag_coverage_subquery.c.coverage_percentage).label('avg_coverage_percentage')
            )
            .select_from(host_tag_coverage_subquery)
            .group_by(
                host_tag_coverage_subquery.c.tag_name,
                host_tag_coverage_subquery.c.tag_id
            )
            .order_by(
                desc('avg_coverage_percentage')
            )
        )
        
        return session.execute(tag_stats_query).all()
    
    @staticmethod
    def get_outlier_analysis_filtered(session, host_ids=None):
        """
        Identify outliers in host coverage within each site using z-scores,
        filtered by host IDs.
        
        Args:
            session: SQLAlchemy session
            host_ids: List of host IDs to filter by
            
        Returns:
            List of tuples with hostname, site, platform_os, covered_rules, avg_coverage, 
            stddev_coverage, z_score, and performance_category
        """
        # Base host coverage query
        host_coverage_query = (
            select(
                Host.id.label('host_id'),
                Host.hostname,
                Host.site,
                Host.platform_os,
                func.count(distinct(HostSigmaCompliance.sigma_id)).label('covered_rules')
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
            .where(Host.site != None)
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
                Host.site, 
                Host.platform_os
            )
            .subquery()
        )
        
        # Site statistics subquery
        site_stats_subquery = (
            select(
                host_coverage_subquery.c.site,
                func.avg(host_coverage_subquery.c.covered_rules).label('avg_coverage'),
                func.stddev(host_coverage_subquery.c.covered_rules).label('stddev_coverage')
            )
            .select_from(host_coverage_subquery)
            .group_by(host_coverage_subquery.c.site)
            .subquery()
        )
        
        # Calculate z-score and performance category
        z_score = ((host_coverage_subquery.c.covered_rules - site_stats_subquery.c.avg_coverage) / 
                   func.nullif(site_stats_subquery.c.stddev_coverage, 0)).label('z_score')
        
        # Define performance category based on z-score
        performance_category = case(
            (z_score < -1, 'Severely Below Average'),
            (z_score < -0.3, 'Below Average'),
            (z_score > 1, 'Exceptionally Above Average'),
            (z_score > 0.3, 'Above Average'),
            else_='Average'
        ).label('performance_category')
        
        # Final query
        query = (
            select(
                host_coverage_subquery.c.hostname,
                host_coverage_subquery.c.site,
                host_coverage_subquery.c.platform_os,
                host_coverage_subquery.c.covered_rules,
                site_stats_subquery.c.avg_coverage,
                site_stats_subquery.c.stddev_coverage,
                z_score,
                performance_category
            )
            .select_from(host_coverage_subquery)
            .join(
                site_stats_subquery, 
                host_coverage_subquery.c.site == site_stats_subquery.c.site
            )
            .where(site_stats_subquery.c.stddev_coverage > 0)
            .order_by(
                func.abs(z_score).desc()
            )
        )
        
        return session.execute(query).all()
    
    @staticmethod
    def get_host_vulnerability_exposure_filtered(session, host_ids=None, limit=10):
        """
        Get host vulnerability exposure to critical rules,
        filtered by host IDs.
        
        Args:
            session: SQLAlchemy session
            host_ids: List of host IDs to filter by
            limit: Maximum number of results to return
            
        Returns:
            List of tuples with hostname, ip_address, missing_critical_rules, critical_rules_missing
        """
        # Get all critical/high severity rules
        critical_rules_subquery = (
            select(
                SigmaRule.id,
                SigmaRule.name,
                SigmaRule.level
            )
            .select_from(SigmaRule)
            .where(
                and_(
                    SigmaRule.deleted == False,
                    SigmaRule.enabled == True,
                    or_(
                        SigmaRule.level == 'critical',
                        SigmaRule.level == 'high'
                    )
                )
            )
            .subquery()
        )
        
        # Get missing critical rules per host
        host_missing_critical_rules_query = (
            select(
                Host.id.label('host_id'),
                Host.hostname,
                Host.ip_address,
                func.array_agg(
                    critical_rules_subquery.c.name
                ).label('critical_rules_missing'),
                func.count(critical_rules_subquery.c.id).label('missing_critical_rules')
            )
            .select_from(Host)
            .join(
                critical_rules_subquery,
                literal(1) == 1  # Cross join
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
                    HostSigmaCompliance.sigma_id == critical_rules_subquery.c.id
                )
            )
            .where(HostSigmaCompliance.id == None)  # Missing rules only
        )
        
        # Apply host ID filter if provided
        if host_ids:
            host_missing_critical_rules_query = host_missing_critical_rules_query.where(Host.id.in_(host_ids))
        
        # Group by and order by
        host_missing_critical_rules_query = (
            host_missing_critical_rules_query
            .group_by(
                Host.id,
                Host.hostname,
                Host.ip_address
            )
            .order_by(
                desc('missing_critical_rules')
            )
            .limit(limit)
        )
        
        return session.execute(host_missing_critical_rules_query).all()
    
    @staticmethod
    def get_host_coverage_by_severity_level_filtered(session, host_ids=None):
        """
        Get host coverage percentage by severity level,
        filtered by host IDs.
        
        Args:
            session: SQLAlchemy session
            host_ids: List of host IDs to filter by
            
        Returns:
            List of tuples with hostname, site, level, covered_rules_count, 
            total_rules_by_level, and coverage_percentage
        """
        # Get total rules by severity level
        total_rules_by_level_subquery = (
            select(
                SigmaRule.level,
                func.count().label('total_rules')
            )
            .select_from(SigmaRule)
            .where(
                and_(
                    SigmaRule.enabled == True,
                    SigmaRule.deleted == False
                )
            )
            .group_by(
                SigmaRule.level
            )
            .subquery()
        )
        
        # Base query for host coverage by severity level
        host_severity_coverage_query = (
            select(
                Host.hostname,
                Host.site,
                SigmaRule.level,
                func.count(distinct(HostSigmaCompliance.sigma_id)).label('covered_rules_count'),
                total_rules_by_level_subquery.c.total_rules.label('total_rules_by_level'),
                (func.count(distinct(HostSigmaCompliance.sigma_id)) * 100.0 / 
                 total_rules_by_level_subquery.c.total_rules).label('coverage_percentage')
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
                total_rules_by_level_subquery,
                SigmaRule.level == total_rules_by_level_subquery.c.level
            )
        )
        
        # Apply host ID filter if provided
        if host_ids:
            host_severity_coverage_query = host_severity_coverage_query.where(Host.id.in_(host_ids))
        
        # Group by and order by
        host_severity_coverage_query = (
            host_severity_coverage_query
            .group_by(
                Host.hostname,
                Host.site,
                SigmaRule.level,
                total_rules_by_level_subquery.c.total_rules
            )
            .order_by(
                SigmaRule.level,
                desc('coverage_percentage')
            )
        )
        
        return session.execute(host_severity_coverage_query).all()
    
    @staticmethod
    def get_gap_analysis_filtered(session, host_ids=None):
        """
        Get gap analysis showing hosts with the highest percentage of missing rules,
        filtered by host IDs.
        
        Args:
            session: SQLAlchemy session
            host_ids: List of host IDs to filter by
            
        Returns:
            List of tuples with hostname, ip_address, platform_os, 
            missing_rules_count, and gap_percentage
        """
        # Get total enabled rules count
        total_rules_subquery = (
            select(func.count())
            .select_from(SigmaRule)
            .where(
                and_(
                    SigmaRule.enabled == True,
                    SigmaRule.deleted == False
                )
            )
            .scalar_subquery()
        )
        
        # Base query for host rule coverage
        host_rule_coverage_query = (
            select(
                Host.id.label('host_id'),
                Host.hostname,
                Host.ip_address,
                Host.platform_os,
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
            host_rule_coverage_query = host_rule_coverage_query.where(Host.id.in_(host_ids))
        
        # Group by and create subquery
        host_rule_coverage_subquery = (
            host_rule_coverage_query
            .group_by(
                Host.id,
                Host.hostname,
                Host.ip_address,
                Host.platform_os
            )
            .subquery()
        )
        
        # Final query to calculate gaps
        gap_query = (
            select(
                host_rule_coverage_subquery.c.hostname,
                host_rule_coverage_subquery.c.ip_address,
                host_rule_coverage_subquery.c.platform_os,
                (total_rules_subquery - host_rule_coverage_subquery.c.covered_rules_count).label('missing_rules_count'),
                ((total_rules_subquery - host_rule_coverage_subquery.c.covered_rules_count) * 100.0 / 
                 total_rules_subquery).label('gap_percentage')
            )
            .select_from(host_rule_coverage_subquery)
            .order_by(
                desc('gap_percentage')
            )
        )
        
        return session.execute(gap_query).all()


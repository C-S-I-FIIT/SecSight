from sqlalchemy import func, desc, text, case, cast, Float, and_
from app.db.models import Host, HostSigmaCompliance, SigmaRule, MitreTactic, rule_tactics_map, HostConfigReview, MitreTechnique, rule_techniques_map
from app.db.database import Database

def get_rule_coverage_by_host():
    """Get rule coverage statistics by host"""
    db = Database()
    with db.session() as session:
        # Create all possible host-sigma rule pairs
        all_pairs = session.query(
            Host.id.label('host_id'),
            Host.hostname,
            SigmaRule.id.label('sigma_id')
        ).select_from(Host).join(SigmaRule, text('1=1')).subquery()

        # Get latest review matches
        latest_review_matches = session.query(
            HostSigmaCompliance.host_id,
            HostSigmaCompliance.sigma_id
        ).join(
            Host,
            Host.id == HostSigmaCompliance.host_id
        ).filter(
            Host.latest_host_config_review_id == HostSigmaCompliance.host_config_review_id
        ).subquery()

        # Calculate coverage status
        coverage_status = session.query(
            all_pairs.c.host_id,
            all_pairs.c.hostname,
            all_pairs.c.sigma_id,
            case(
                (latest_review_matches.c.sigma_id != None, 'covered'),
                else_='missing'
            ).label('status')
        ).outerjoin(
            latest_review_matches,
            (all_pairs.c.host_id == latest_review_matches.c.host_id) &
            (all_pairs.c.sigma_id == latest_review_matches.c.sigma_id)
        ).subquery()

        # Final aggregation
        result = session.query(
            coverage_status.c.host_id,
            coverage_status.c.hostname,
            func.count().label('total_rules'),
            func.count().filter(coverage_status.c.status == 'covered').label('covered_rules'),
            cast(
                func.count().filter(coverage_status.c.status == 'covered') * 100.0 / func.count(),
                Float
            ).label('coverage_percentage')
        ).group_by(
            coverage_status.c.host_id,
            coverage_status.c.hostname
        ).all()

        return result

def get_rule_coverage_stats():
    """Get overall rule coverage statistics"""
    db = Database()
    with db.session() as session:
        # Create all possible host-sigma rule pairs
        all_pairs = session.query(
            Host.id.label('host_id'),
            SigmaRule.id.label('sigma_id')
        ).select_from(Host).join(SigmaRule, text('1=1')).subquery()

        # Get latest review matches
        latest_review_matches = session.query(
            HostSigmaCompliance.sigma_id
        ).join(
            Host,
            Host.id == HostSigmaCompliance.host_id
        ).filter(
            Host.latest_host_config_review_id == HostSigmaCompliance.host_config_review_id
        ).distinct().subquery()

        # Calculate coverage
        result = session.query(
            func.count(func.distinct(all_pairs.c.sigma_id)).label('total_rules'),
            func.count(func.distinct(all_pairs.c.sigma_id)).filter(
                latest_review_matches.c.sigma_id != None
            ).label('covered_rules')
        ).outerjoin(
            latest_review_matches,
            all_pairs.c.sigma_id == latest_review_matches.c.sigma_id
        ).first()

        return result

def get_rule_coverage_by_tactic():
    """Get rule coverage by MITRE tactic"""
    db = Database()
    with db.session() as session:
        # Create all tactic-sigma rule pairs
        all_pairs = session.query(
            MitreTactic.name.label('tactic_name'),
            SigmaRule.id.label('sigma_id')
        ).join(
            rule_tactics_map,
            MitreTactic.tactic_id == rule_tactics_map.c.tactic_id
        ).join(
            SigmaRule,
            SigmaRule.id == rule_tactics_map.c.sigma_rule_id
        ).subquery()

        # Get latest review matches
        latest_review_matches = session.query(
            HostSigmaCompliance.sigma_id
        ).join(
            Host,
            Host.id == HostSigmaCompliance.host_id
        ).filter(
            Host.latest_host_config_review_id == HostSigmaCompliance.host_config_review_id
        ).distinct().subquery()

        # Calculate coverage by tactic
        result = session.query(
            all_pairs.c.tactic_name,
            func.count(func.distinct(all_pairs.c.sigma_id)).label('total_rules'),
            func.count(func.distinct(all_pairs.c.sigma_id)).filter(
                latest_review_matches.c.sigma_id != None
            ).label('covered_rules'),
            cast(
                func.count(func.distinct(all_pairs.c.sigma_id)).filter(
                    latest_review_matches.c.sigma_id != None
                ) * 100.0 / func.count(func.distinct(all_pairs.c.sigma_id)),
                Float
            ).label('coverage_percentage')
        ).outerjoin(
            latest_review_matches,
            all_pairs.c.sigma_id == latest_review_matches.c.sigma_id
        ).group_by(
            all_pairs.c.tactic_name
        ).all()

        return result

def get_host_coverage_timeline(host_ids=None, limit=None):
    """Get coverage timeline for selected hosts"""
    db = Database()
    with db.session() as session:
        # Get timeline data
        timeline_data = session.query(
            Host.hostname,
            HostConfigReview.created_at,
            HostSigmaCompliance.sigma_id,
            HostSigmaCompliance.host_config_review_id
        ).join(
            Host,
            Host.id == HostConfigReview.host_id
        ).join(
            HostSigmaCompliance,
            HostConfigReview.id == HostSigmaCompliance.host_config_review_id
        )

        if host_ids:
            timeline_data = timeline_data.filter(Host.id.in_(host_ids))

        timeline_data = timeline_data.subquery()

        # Calculate coverage over time
        result = session.query(
            timeline_data.c.hostname,
            timeline_data.c.created_at,
            func.count(func.distinct(timeline_data.c.sigma_id)).label('total_rules'),
            func.count(func.distinct(timeline_data.c.sigma_id)).filter(
                timeline_data.c.host_config_review_id != None
            ).label('covered_rules'),
            cast(
                func.count(func.distinct(timeline_data.c.sigma_id)).filter(
                    timeline_data.c.host_config_review_id != None
                ) * 100.0 / func.count(func.distinct(timeline_data.c.sigma_id)),
                Float
            ).label('coverage_percentage')
        ).group_by(
            timeline_data.c.hostname,
            timeline_data.c.created_at
        ).order_by(
            timeline_data.c.hostname,
            timeline_data.c.created_at
        )

        if limit:
            result = result.limit(limit)

        return result.all()

def get_sigma_rules_per_tactic():
    """Get count of Sigma rules per MITRE tactic"""
    db = Database()
    with db.session() as session:
        result = session.query(
            MitreTactic.tactic_id,
            MitreTactic.name.label('tactic_name'),
            func.count(func.distinct(SigmaRule.id)).label('rule_count')
        ).outerjoin(
            rule_tactics_map,
            MitreTactic.id == rule_tactics_map.c.tactic_id
        ).outerjoin(
            SigmaRule,
            SigmaRule.id == rule_tactics_map.c.sigma_rule_id
        ).group_by(
            MitreTactic.tactic_id,
            MitreTactic.name
        ).order_by(
            MitreTactic.tactic_id
        ).all()
        
        return result 

def get_sigma_coverage_stats_per_tactic(host_ids=None):
    """Get Sigma rule coverage statistics per MITRE tactic"""
    db = Database()
    with db.session() as session:
        # First get all tactics
        all_tactics = session.query(
            MitreTactic.tactic_id,
            MitreTactic.name.label('tactic_name')
        ).all()
        
        # Get all hosts
        hosts_query = session.query(Host)
        if host_ids:
            hosts_query = hosts_query.filter(Host.id.in_(host_ids))
        all_hosts = hosts_query.all()
        
        # Create the rule coverage CTE
        rule_coverage = session.query(
            MitreTactic.tactic_id,
            MitreTactic.name.label('tactic_name'),
            Host.hostname,
            func.count(func.distinct(case((HostSigmaCompliance.sigma_id.isnot(None), SigmaRule.id)))).label('covered_rules'),
            func.count(func.distinct(SigmaRule.id)).label('total_rules'),
            func.round(
                func.coalesce(
                    func.count(func.distinct(case((HostSigmaCompliance.sigma_id.isnot(None), SigmaRule.id)))) * 100.0 / 
                    func.nullif(func.count(func.distinct(SigmaRule.id)), 0),
                    0
                ),
                2
            ).label('coverage_percentage')
        ).select_from(MitreTactic)\
        .outerjoin(rule_tactics_map, MitreTactic.id == rule_tactics_map.c.tactic_id)\
        .outerjoin(SigmaRule, rule_tactics_map.c.sigma_rule_id == SigmaRule.id)\
        .join(Host, text('1=1'))\
        .outerjoin(
            HostSigmaCompliance,
            and_(
                HostSigmaCompliance.sigma_id == SigmaRule.id,
                HostSigmaCompliance.host_id == Host.id,
                HostSigmaCompliance.host_config_review_id == Host.latest_host_config_review_id
            )
        )

        # Apply host filter if provided
        if host_ids:
            rule_coverage = rule_coverage.filter(Host.id.in_(host_ids))

        rule_coverage = rule_coverage.group_by(
            MitreTactic.tactic_id,
            MitreTactic.name,
            Host.hostname
        ).subquery()

        # Get individual host statistics
        host_stats = session.query(
            rule_coverage.c.tactic_id,
            rule_coverage.c.tactic_name,
            rule_coverage.c.hostname,
            rule_coverage.c.coverage_percentage.label('host_coverage')
        ).order_by(
            rule_coverage.c.tactic_id,
            rule_coverage.c.hostname
        ).all()
        
        # Create a complete set of host statistics with zero coverage for missing combinations
        complete_host_stats = []
        for host in all_hosts:
            for tactic in all_tactics:
                # Find existing coverage for this host-tactic combination
                existing_coverage = next(
                    (stat for stat in host_stats if 
                     stat.hostname == host.hostname and 
                     stat.tactic_id == tactic.tactic_id),
                    None
                )
                
                if existing_coverage:
                    complete_host_stats.append(existing_coverage)
                else:
                    # Create a new entry with zero coverage
                    complete_host_stats.append((
                        tactic.tactic_id,
                        tactic.tactic_name,
                        host.hostname,
                        0.0  # Zero coverage
                    ))

        # Get aggregated statistics
        agg_stats = session.query(
            rule_coverage.c.tactic_id,
            rule_coverage.c.tactic_name,
            func.round(func.coalesce(func.min(rule_coverage.c.coverage_percentage), 0), 2).label('min_coverage'),
            func.round(func.coalesce(func.avg(rule_coverage.c.coverage_percentage), 0), 2).label('avg_coverage'),
            func.round(func.coalesce(func.max(rule_coverage.c.coverage_percentage), 0), 2).label('max_coverage')
        ).group_by(
            rule_coverage.c.tactic_id,
            rule_coverage.c.tactic_name
        ).order_by(
            rule_coverage.c.tactic_id
        ).all()

        return {
            'aggregated': agg_stats,
            'individual': complete_host_stats
        }

def host_compliance_to_sigma_and_tactic():
    """
    Generate two tables:
    1. Host compliance with each Sigma rule (1=compliant, 0=non-compliant)
    2. Host coverage percentage for each MITRE tactic
    
    Returns:
        tuple: (host_rule_matrix, host_tactic_coverage)
    """
    db = Database()
    with db.session() as session:
        # Get all hosts
        hosts = session.query(Host).all()
        
        # Get all sigma rules and create a list of their IDs
        sigma_rules = session.query(SigmaRule).all()
        rule_ids = [rule.id for rule in sigma_rules]
        
        # Get all MITRE tactics and create a list of their IDs
        tactics = session.query(MitreTactic).all()
        tactic_ids = [tactic.id for tactic in tactics]
        
        # Calculate the number of sigma rules per tactic
        tactic_rule_counts = {}
        for tactic in tactics:
            # Count rules associated with this tactic
            count = session.query(func.count(SigmaRule.id)).join(
                rule_tactics_map,
                SigmaRule.id == rule_tactics_map.c.sigma_rule_id
            ).filter(
                rule_tactics_map.c.tactic_id == tactic.id
            ).scalar()
            
            tactic_rule_counts[tactic.id] = count
        
        # Initialize result tables as lists of dictionaries
        host_rule_matrix = []
        host_tactic_coverage = []
        
        # Process each host
        for host in hosts:
            # Create dictionaries for this host's data
            rule_data = {}
            tactic_data = {}
            
            # Always add hostname to the output
            rule_data["hostname"] = host.hostname
            tactic_data["hostname"] = host.hostname
            
            if host.latest_host_config_review_id is None:
                # Host has no latest review, fill with zeros
                for rule_id in rule_ids:
                    rule_data[f"rule_{rule_id}"] = 0
                
                for tactic_id in tactic_ids:
                    tactic_data[f"tactic_{tactic_id}"] = 0
            else:
                # Get compliant sigma rules for this host's latest review
                compliant_rules = session.query(HostSigmaCompliance.sigma_id).filter(
                    HostSigmaCompliance.host_id == host.id,
                    HostSigmaCompliance.host_config_review_id == host.latest_host_config_review_id
                ).all()
                
                # Convert to set for faster lookup
                compliant_rule_ids = {r.sigma_id for r in compliant_rules}
                
                # Fill rule compliance data
                for rule_id in rule_ids:
                    is_compliant = 1 if rule_id in compliant_rule_ids else 0
                    rule_data[f"rule_{rule_id}"] = is_compliant
                
                # Initialize tactic coverage counts
                tactic_covered_counts = {tactic_id: 0 for tactic_id in tactic_ids}
                
                # For each compliant rule, find associated tactics and increment counts
                for rule_id in compliant_rule_ids:
                    # Get tactics associated with this rule
                    rule_tactics = session.query(rule_tactics_map.c.tactic_id).filter(
                        rule_tactics_map.c.sigma_rule_id == rule_id
                    ).all()
                    
                    # Increment count for each associated tactic
                    for tactic_mapping in rule_tactics:
                        tactic_id = tactic_mapping.tactic_id
                        if tactic_id in tactic_covered_counts:
                            tactic_covered_counts[tactic_id] += 1
                
                # Calculate coverage percentage for each tactic
                for tactic_id in tactic_ids:
                    total_rules = tactic_rule_counts.get(tactic_id, 0)
                    covered_rules = tactic_covered_counts.get(tactic_id, 0)
                    
                    # Calculate coverage ratio, avoid division by zero
                    if total_rules > 0:
                        coverage = covered_rules / total_rules
                    else:
                        coverage = 0.0
                    
                    tactic_data[f"tactic_{tactic_id}"] = coverage
            
            # Add the data to result lists
            host_rule_matrix.append(rule_data)
            host_tactic_coverage.append(tactic_data)
        
        return host_rule_matrix, host_tactic_coverage

def get_technique_coverage_by_tactic():
    """Get count of Sigma rules covering each MITRE technique grouped by tactic"""
    db = Database()
    with db.session() as session:
        result = session.query(
            MitreTactic.tactic_id.label('tactic_id'),
            MitreTactic.name.label('tactic_name'),
            MitreTechnique.technique_id.label('technique_id'),
            MitreTechnique.name.label('technique_name'),
            func.count(func.distinct(SigmaRule.id)).label('rules_covering')
        ).join(
            rule_tactics_map,
            MitreTactic.id == rule_tactics_map.c.tactic_id
        ).join(
            SigmaRule,
            SigmaRule.id == rule_tactics_map.c.sigma_rule_id
        ).join(
            rule_techniques_map,
            SigmaRule.id == rule_techniques_map.c.sigma_rule_id
        ).join(
            MitreTechnique,
            MitreTechnique.id == rule_techniques_map.c.technique_id
        ).join(
            HostSigmaCompliance,
            SigmaRule.id == HostSigmaCompliance.sigma_id
        ).group_by(
            MitreTactic.tactic_id,
            MitreTactic.name,
            MitreTechnique.technique_id,
            MitreTechnique.name
        ).order_by(
            desc('rules_covering')
        ).all()
        
        return result



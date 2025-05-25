import os
import argparse
from dotenv import load_dotenv
from app.db.database import Database

from app.mappings import *
from app.mappings.windows_mappings import SERVICE_STATUS, windows_event_log_mapping, mitre_tactics
from app.mappings.sysmon_mappings import sysmon_event_mappings
from datetime import datetime
from app.db.models import Host, HostConfigReview, HostConfigReviewEntry, SigmaRule, HostSigmaCompliance, MitreTactic, MitreTechnique, NetBoxTag, tag_device_rule_map, SigmaWindowsLogSource, sigma_rule_windows_log_map
from app.mappings.windows_mappings import SERVICE_STATUS

from app.clients import WinClient, VaultClient, WinRMClient
from app.collectors import KibanaCollector, MitreCollector, TheHiveCollector, SigmaRuleParser, NetboxClient


from alembic import command
from alembic.config import Config


import json, yaml
from typing import Dict, Any, Union, Optional

from loguru import logger


import urllib3
urllib3.disable_warnings()


load_dotenv()

def create_host_entries(db, hosts):
    """Create or update host entries in the database from Netbox hosts."""
    logger.info("Creating or updating host entries in database...")
    for host_info in hosts:
        if host_info.get('ip') is None:
            logger.warning(f"Skipping host {host_info.get('hostname', 'unknown')} with no IP address")
            continue
        try:
            with db.session() as session:
                host = session.query(Host).filter_by(hostname=host_info['hostname']).first()
                if not host:
                    # Create a new host entry with careful handling of potentially missing fields
                    host = Host(
                        hostname=host_info['hostname'],
                        ip_address=host_info['ip'],
                        netbox_id=host_info.get('netbox_id'),  # Use .get() to handle None safely
                        platform_os=host_info.get('platform_os'),
                        comment=f"Imported from Netbox on {datetime.now()}",
                        role=host_info.get('role'),
                        manufacturer=host_info.get('manufacturer'),
                        model=host_info.get('model'),
                        status=host_info.get('status'),
                        site=host_info.get('site'),
                        location=host_info.get('location'),
                        url=host_info.get('url'),
                        is_vm=host_info.get('is_vm', False),
                        cluster=host_info.get('cluster'),
                        dns_name=host_info.get('ip_info', {}).get('dns_name'),
                        ip_description=host_info.get('ip_info', {}).get('description'),
                        prefix_name=host_info.get('prefix_info', {}).get('name'),
                        prefix_description=host_info.get('prefix_info', {}).get('description'),
                        vlan_id=host_info.get('prefix_info', {}).get('vlan_id'),
                        vlan_name=host_info.get('prefix_info', {}).get('vlan_name'),
                        vlan_display=host_info.get('prefix_info', {}).get('vlan_display')
                    )
                    session.add(host)
                    session.commit()
                    logger.info(f"Created host entry for {host_info['hostname']}")
                else:
                    # Update existing host entry with new data
                    host.ip_address = host_info['ip']
                    host.netbox_id = host_info.get('netbox_id')
                    host.platform_os = host_info.get('platform_os')
                    host.comment = f"Updated from Netbox on {datetime.now()}"
                    host.role = host_info.get('role')
                    host.manufacturer = host_info.get('manufacturer')
                    host.model = host_info.get('model')
                    host.status = host_info.get('status')
                    host.site = host_info.get('site')
                    host.location = host_info.get('location')
                    host.url = host_info.get('url')
                    host.is_vm = host_info.get('is_vm', False)
                    host.cluster = host_info.get('cluster')
                    host.dns_name = host_info.get('ip_info', {}).get('dns_name')
                    host.ip_description = host_info.get('ip_info', {}).get('description')
                    host.prefix_name = host_info.get('prefix_info', {}).get('name')
                    host.prefix_description = host_info.get('prefix_info', {}).get('description')
                    host.vlan_id = host_info.get('prefix_info', {}).get('vlan_id')
                    host.vlan_name = host_info.get('prefix_info', {}).get('vlan_name')
                    host.vlan_display = host_info.get('prefix_info', {}).get('vlan_display')
                    session.commit()
                    logger.info(f"Updated host entry for {host_info['hostname']}")
                
                # Handle tags - remove existing tag mappings and recreate them
                if host_info.get('tags'):
                    # Delete existing tag mappings for this host
                    session.execute(
                        tag_device_rule_map.delete().where(tag_device_rule_map.c.device_id == host.id)
                    )
                    session.commit()
                    
                    # Add or update tags
                    for tag in host_info['tags']:
                        existing_tag = session.query(NetBoxTag).filter_by(netbox_id=tag.get('netbox_id')).first()
                        if existing_tag:
                            # Update existing tag if details have changed
                            existing_tag.name = tag.get('name', existing_tag.name)
                            existing_tag.color = tag.get('color', existing_tag.color)
                            netbox_tag = existing_tag
                        else:
                            # Create new tag
                            netbox_tag = NetBoxTag(
                                name=tag.get('name'),
                                color=tag.get('color'),
                                netbox_id=tag.get('netbox_id')
                            )
                            session.add(netbox_tag)
                            session.commit()
                        
                        # Create mapping between host and tag
                        tags_mapping = tag_device_rule_map.insert().values(
                            tag_id=netbox_tag.id,
                            device_id=host.id
                        )
                        
                        session.execute(tags_mapping)
                    session.commit()
        except Exception as e:
            logger.error(f"Error creating or updating host entry for {host_info.get('hostname', 'unknown')}: {str(e)}")

def process_windows_hosts(db, hosts):
    """Process Windows hosts and their Winlogbeat configurations."""
    
    for host_info in hosts:
        # Skip non-Windows hosts
        if host_info.get('platform_os') is None:
            continue
            
        if not host_info.get('platform_os', '').lower().startswith('windows'):
            continue
            
        try:
            hostname = host_info.get('hostname', 'unknown_host')
            logger.info(f"Processing Windows host: {hostname}")
            
            with db.session() as session:
                host = session.query(Host).filter_by(hostname=hostname).first()
                if not host:
                    logger.warning(f"Host {hostname} not found in database, skipping...")
                    continue
                
                try:
                    ip = host_info.get('ip', '').split('/')[0]  # Safely get IP
                    if not ip:
                        logger.error(f"No valid IP address for {hostname}, skipping...")
                        continue
                        
                    win_client = WinClient(ip)
                    
                    # Check Winlogbeat
                    winlogbeat_status = win_client.get_winlogbeat_status()
                    
                    if winlogbeat_status == SERVICE_STATUS[0]: # 0 = NotInstalled
                        logger.warning(f"Winlogbeat is not installed on {hostname}")
                        continue
                    
                    if winlogbeat_status != SERVICE_STATUS[4]: # 4 = Running
                        logger.warning(f"Winlogbeat is not running on {hostname}")
                        continue
                    
                    # Create new config review only if we can connect and get config
                    review = HostConfigReview(
                        host_id=host.id
                    )
                    session.add(review)
                    session.commit()
                    
                    # Parse configuration and add entries
                    winlogbeat_config = win_client.get_winlogbeat_config()
                
                    if not winlogbeat_config:
                        logger.error(f"[WinClient] [WINLOGBEAT] Failed to get winlogbeat config for {hostname}, IP:{ip}")
                        continue
                        
                    event_logs = winlogbeat_config.get('winlogbeat.event_logs')
                    
                    if not event_logs:
                        logger.error(f"[WinClient] [WINLOGBEAT] No event logs found for {hostname}, IP:{ip}")
                        continue
                    
                    for event_log in event_logs:
                        log_name = event_log.get('name')
                        if not log_name:
                            logger.warning(f"Event log missing name for {hostname}, skipping...")
                            continue
                            
                        event_ids = event_log.get('event_id')
                        # Handle both single event_id and list of event_ids
                        if event_ids is None:
                            entry = HostConfigReviewEntry(
                                host_config_review_id=review.id,
                                name=log_name,
                                event_id=None
                            )
                            session.add(entry)
                        else:
                            for event_id in event_ids.split(','):
                                entry = HostConfigReviewEntry(
                                    host_config_review_id=review.id,
                                    name=log_name,
                                    event_id=event_id.strip()
                                )
                                session.add(entry)
                            
                    # Update host's latest review
                    host.latest_host_config_review_id = review.id
                    session.commit()
                    
                    logger.info(f"Successfully processed Winlogbeat configuration for {hostname}")
                        
                except Exception as e:
                    logger.error(f"Error connecting to or processing Winlogbeat for {hostname}: {str(e)}")
                    session.rollback()
                
        except Exception as e:
            logger.error(f"Error processing host {host_info.get('hostname', 'unknown')}: {str(e)}")


def calculate_sigma_coverage(db):
    """Calculate and populate host sigma compliance based on host config reviews."""
    logger.info("Calculating sigma coverage...")
    
    try:
        with db.session() as session:
            # Get all hosts with their latest config review IDs
            hosts = session.query(Host).filter(Host.latest_host_config_review_id.isnot(None)).all()
            
            for host in hosts:
                logger.info("")
                logger.info(f" ==== Processing host: {host.hostname} ==== ")
                logger.info("")
                
                # Get all entries for this host's latest config review
                entries = session.query(HostConfigReviewEntry).filter_by(
                    host_config_review_id=host.latest_host_config_review_id
                ).all()
                
                _info = {}
                
                for entry in entries:
                    #logger.debug(f"Processing entry: {entry.name}")
                    # Get the event log name from the entry
                    event_log_name = entry.name
                    
                    # Look up the event log in the mapping values
                    matching_keys = []
                    for key, value in windows_event_log_mapping.items():
                        if isinstance(value, str):
                            if value == event_log_name:
                                matching_keys.append(key)
                        elif isinstance(value, list):
                            if event_log_name in value:
                                matching_keys.append(key)
                    
                    if not matching_keys:
                        logger.debug(f"Event log [{event_log_name}] not found in any mapping values, skipping...")
                        continue
                        
                    # Process each matching key
                    #logger.info(f"Matching keys: {matching_keys}")
                    for key in matching_keys:
                        # Get the mapped values (convert to list if it's a string)
                        mapped_values = windows_event_log_mapping[key]
                        if isinstance(mapped_values, str):
                            mapped_values = [mapped_values]
                        # Find sigma rules that match this log source by category or service
                        matching_rules = session.query(SigmaRule).filter(
                            (SigmaRule.log_source_category == key) |
                            (SigmaRule.log_source_service == key)
                        ).all()
                        
                        if not matching_rules:
                            #logger.warning(f"No matching sigma rules found for {key}")
                            continue
                            
                        #logger.info(f"Found {len(matching_rules)} matching sigma rules for {key}")
                        
                        for rule in matching_rules:
                            # Check if this combination already exists
                            existing = session.query(HostSigmaCompliance).filter_by(
                                host_id=host.id,
                                host_config_review_id=host.latest_host_config_review_id,
                                sigma_id=rule.id
                            ).first()
                            
                            if not existing:
                                # Create new compliance entry
                                compliance = HostSigmaCompliance(
                                    host_id=host.id,
                                    host_config_review_id=host.latest_host_config_review_id,
                                    sigma_id=rule.id
                                )
                                session.add(compliance)
                        
                        #logger.debug(f"Compliance Added for: {len(matching_rules)} (Matching rules) [{event_log_name}]")
                        #logger.debug("\n\n\tDetailed Added Compliances (Rules):\n" + "".join([f"\t\t- [{rule.rule_id}] {rule.name}\n" for rule in matching_rules]))
                        
                        _info[event_log_name] = matching_rules
                
                _msg = "\n\nCompliance Info:\n\n"
                for event_log_name, matching_rules in _info.items():
                    _msg += f"\t\tEvent Log: {event_log_name}\n"
                    _msg += "\t\tMatching Rules:\n"
                    for rule in matching_rules:
                        _msg += f"\t\t\t- [{rule.rule_id}] {rule.name}\n"
                    _msg += "\n\t\t----------------------------------------\n"
                logger.debug(_msg)
                        
                #logger.info("")
                #logger.info(f" ========================================== ")
                #logger.info("")
                
                session.commit()
                
        logger.success("Successfully calculated sigma coverage")
        
    except Exception as e:
        logger.error(f"Error calculating sigma coverage: {str(e)}")
        session.rollback()


def run_migrations():
    try:
        alembic_cfg = Config("alembic.ini")
        command.upgrade(alembic_cfg, "head")
        logger.info("Database migrations completed successfully")
    except Exception as e:
        logger.error(f"Error during database migrations: {str(e)}")
        logger.info("Attempting to continue despite migration issues")
        logger.critical("Database migrations failed, please check the database schema and run the migrations again")
        exit(1)

def populate_windows_event_log_mappings(db):
    """Populate the SigmaWindowsLogSource table with mappings from windows_mappings.py and sysmon_mappings.py"""
    logger.info("Populating Windows event log mappings...")
    
    try:
        with db.session() as session:
            # Instead of deleting all existing mappings, we'll track and update them
            # First, get all existing log sources for reference
            existing_log_sources = {
                (ls.sigma_log_source, ls.windows_event_channel, ls.event_id): ls 
                for ls in session.query(SigmaWindowsLogSource).all()
            }
            
            # Clear existing rule mappings but keep the log sources
            session.execute(sigma_rule_windows_log_map.delete())
            session.commit()
            
            # Track new mappings to be created
            new_log_sources = []
            
            # Process windows_event_log_mapping
            for sigma_source, channels in windows_event_log_mapping.items():
                # Handle both single channels and lists of channels
                if isinstance(channels, str):
                    channel_list = [channels]
                else:
                    channel_list = channels
                
                for channel in channel_list:
                    # Check if this mapping already exists
                    key = (sigma_source, channel, None)
                    if key in existing_log_sources:
                        # Already exists, no need to create
                        continue
                    
                    # Create new log source
                    log_source = SigmaWindowsLogSource(
                        sigma_log_source=sigma_source,
                        windows_event_channel=channel,
                        event_id=None
                    )
                    new_log_sources.append(log_source)
            
            # Process sysmon_event_mappings
            for channel, events in sysmon_event_mappings.items():
                for source_type, event_ids in events.items():
                    for event_id in event_ids:
                        # Check if this mapping already exists
                        key = (source_type, channel, event_id)
                        if key in existing_log_sources:
                            # Already exists, no need to create
                            continue
                        
                        # Create new log source
                        log_source = SigmaWindowsLogSource(
                            sigma_log_source=source_type,
                            windows_event_channel=channel,
                            event_id=event_id
                        )
                        new_log_sources.append(log_source)
            
            # Add all new log sources at once
            if new_log_sources:
                session.add_all(new_log_sources)
                session.commit()
                logger.info(f"Added {len(new_log_sources)} new log source mappings")
            else:
                logger.info("No new log source mappings needed")
            
            # Get all log sources again after adding new ones
            all_log_sources = session.query(SigmaWindowsLogSource).all()
            log_source_by_key = {
                (ls.sigma_log_source, ls.windows_event_channel, ls.event_id): ls 
                for ls in all_log_sources
            }
            
            # Now associate sigma rules with their corresponding log sources
            sigma_rules = session.query(SigmaRule).all()
            mapping_count = 0
            
            for rule in sigma_rules:
                # Try to match by log_source_category first
                if rule.log_source_category:
                    log_sources = [
                        ls for ls in all_log_sources 
                        if ls.sigma_log_source == rule.log_source_category
                    ]
                    
                    for log_source in log_sources:
                        # Create mapping between sigma rule and log source
                        mapping = sigma_rule_windows_log_map.insert().values(
                            sigma_rule_id=rule.id,
                            windows_log_source_id=log_source.id
                        )
                        session.execute(mapping)
                        mapping_count += 1
                
                # Then try to match by log_source_service if it's different
                if rule.log_source_service and rule.log_source_service != rule.log_source_category:
                    log_sources = [
                        ls for ls in all_log_sources 
                        if ls.sigma_log_source == rule.log_source_service
                    ]
                    
                    for log_source in log_sources:
                        # Create mapping between sigma rule and log source
                        mapping = sigma_rule_windows_log_map.insert().values(
                            sigma_rule_id=rule.id,
                            windows_log_source_id=log_source.id
                        )
                        session.execute(mapping)
                        mapping_count += 1
            
            session.commit()
            logger.success(f"Successfully populated Windows event log mappings with {mapping_count} rule-to-source relationships")
            
    except Exception as e:
        logger.error(f"Error populating Windows event log mappings: {str(e)}")
        session.rollback()

def run_collector(args):
    """Run the collector based on command line arguments"""
    db = Database()
    
    # Initialize collectors based on arguments
    if args.mitre or args.all:
        mitre_version = "16.0"  # Default version
        force_update = False
        
        # Handle --mitre=value case
        if isinstance(args.mitre, str):
            if args.mitre.lower() == "force":
                force_update = True
            else:
                mitre_version = args.mitre
                
        logger.info(f"Running MITRE collector with version {mitre_version} (force_update={force_update})")
        mitre_collector = MitreCollector(version=mitre_version)
        mitre_collector.collect(force_update=force_update)
    
    # Handle Netbox collection
    if args.netbox or args.all:
        netbox_client = NetboxClient()
        
        # Determine if we only want Windows hosts
        only_windows = args.netbox_windows_only or False
        
        logger.info(f"Getting hosts from Netbox (only_windows={only_windows})")
        hosts = netbox_client.get_all_hosts(only_windows=only_windows)
        
        # Create host entries
        create_host_entries(db, hosts)
        
        # Process Windows hosts if requested
        if args.winlogbeat or args.all:
            logger.info("Processing Winlogbeat configurations for Windows hosts")
            process_windows_hosts(db, hosts)
    elif args.winlogbeat:
        # If --winlogbeat is specified but not --netbox
        logger.warning("--winlogbeat requires --netbox, skipping Winlogbeat processing")
    
    # Handle Sigma rule processing
    sigma_rules_path = args.sigma_rules_path or os.environ.get('SIGMA_RULES_PATH')
    
    if (args.sigma or args.all) and sigma_rules_path:
        logger.info(f"Processing Sigma rules from {sigma_rules_path}")
        sigma_parser = SigmaRuleParser(sigma_rules_path)
        sigma_parser.process_sigma_rules()
        
        # Populate Windows event log mappings
        populate_windows_event_log_mappings(db)
        
        # Calculate sigma coverage
        calculate_sigma_coverage(db)
        
        # Collect Kibana rules
        kibana_collector = KibanaCollector()
        kibana_collector.collect_kibana_rules()
    elif (args.sigma or args.all) and not sigma_rules_path:
        logger.error("Sigma rules path not provided via --sigma-rules-path or SIGMA_RULES_PATH environment variable")
    
    # Handle TheHive collection
    if args.thehive or args.all:
        logger.info("Running TheHive collector")
        hive_collector = TheHiveCollector()
        hive_collector.sync_all()

def parse_args():
    """Parse command line arguments"""
    parser = argparse.ArgumentParser(description="Log Optimization Data Collector")
    
    # MITRE arguments
    parser.add_argument("--mitre", "-m", nargs="?", const=True, 
                        help="Run MITRE collector, optionally specify version or 'force' to force update")
    
    # Netbox arguments
    parser.add_argument("--netbox", "-n", action="store_true", 
                        help="Get hosts from Netbox and update database")
    parser.add_argument("--netbox-windows-only", action="store_true", 
                        help="Only collect Windows hosts from Netbox")
    
    # Winlogbeat arguments
    parser.add_argument("--winlogbeat", "-w", action="store_true", 
                        help="Process Winlogbeat configurations (requires --netbox)")
    
    # Sigma arguments
    parser.add_argument("--sigma", "-s", action="store_true", 
                        help="Process Sigma rules and calculate coverage")
    parser.add_argument("--sigma-rules-path", "-p", 
                        help="Path to Sigma rules directory (optional, can be set via SIGMA_RULES_PATH env var)")
    
    # TheHive arguments
    parser.add_argument("--thehive", "-t", action="store_true", 
                        help="Run TheHive collector with sync_all")
    
    # Logging arguments
    parser.add_argument("--verbose", "-v", action="count", default=0, 
                        help="Enable verbose logging (use -v for INFO with basic format, -vv for DEBUG with full format)")
    
    # Run all collectors
    parser.add_argument("--all", "-a", action="store_true", 
                        help="Run all collectors (requires Sigma rules path via argument or env var)")
    
    return parser.parse_args()

def setup_logging(verbose=0):
    """Setup loguru logging based on verbosity
    
    verbose:
        0 - INFO level with basic format
        1 - DEBUG level with basic format
        2 - DEBUG level with full format including module names
    """
    logger.remove()  # Remove default logger
    
    if verbose == 0:
        # Normal mode: INFO level with basic format
        log_level = "INFO"
        log_format = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <level>{message}</level>"
    elif verbose == 1:
        # Verbose mode: DEBUG level with basic format
        log_level = "DEBUG"
        log_format = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <level>{message}</level>"
    else:
        # Double verbose mode: DEBUG level with module name
        log_level = "DEBUG"
        log_format = "<green>{time:YYYY-MM-DD HH:mm:ss.SSS}</green> | <level>{level: <8}</level> | <blue>{name}</blue>:<blue>{function}</blue>:<blue>{line}</blue> | <level>{message}</level>"
    
    logger.add(
        sys.stderr,
        level=log_level,
        format=log_format
    )
    
    logger.info(f"Logging level set to {log_level}" + (" with full format" if verbose > 1 else ""))

if __name__ == "__main__":
    import sys
    
    # Always reload environment variables at startup
    load_dotenv(override=True)
    
    args = parse_args()
    
    # Setup logging based on verbosity flag
    setup_logging(args.verbose)
    
    # Validate arguments
    sigma_rules_path = args.sigma_rules_path or os.environ.get('SIGMA_RULES_PATH')
    if args.all and not sigma_rules_path:
        logger.error("--all requires Sigma rules path via --sigma-rules-path argument or SIGMA_RULES_PATH environment variable")
        sys.exit(1)
    
    # Run database migrations
    run_migrations()
    
    # Run the collector with the parsed arguments
    run_collector(args)
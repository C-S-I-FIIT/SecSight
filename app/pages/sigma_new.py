import streamlit as st
import pandas as pd
import time
import math
from sqlalchemy.orm import Session
from app.db.database import Database
from app.db.queries.sigma import SigmaQueries
from app.db.queries.additional_host_coverage import AdditionalHostCoverage
from app.db.models import (
    Host, NetBoxTag, tag_device_rule_map, SigmaRule, HostSigmaCompliance
)
from app.db.queries.host import HostQueries
import app.charts as charts

def show_sigma_dashboard():
    """
    Display the Sigma Rules dashboard with host-based filtering.
    """
    st.title("Sigma Rules Dashboard")
    
    # Initialize database connection
    db = Database()
    
    # Create sidebar for host filtering
    st.sidebar.title("Filter Configuration")
    
    # Navigation in sidebar
    view_mode = st.sidebar.radio(
        "Select View",
        ["All Hosts", "Specific Host", "Group of Hosts", "All Enabled Rules"]
    )
    
    # Store filter criteria
    filter_criteria = None
    selected_host_id = None
    
    # Based on view mode, gather filter information
    if view_mode == "Specific Host":
        with db.session() as session:
            # Get all hosts
            hosts = session.query(Host.id, Host.hostname, Host.ip_address).all()
            
            # Create options for selectbox
            host_options = [f"{host.hostname} ({host.ip_address})" for host in hosts]
            host_id_map = {f"{host.hostname} ({host.ip_address})": host.id for host in hosts}
            
            # Host selection
            selected_host = st.sidebar.selectbox(
                "Select Host", 
                options=host_options,
                key=f"host_select_sigma"
            )
            selected_host_id = host_id_map.get(selected_host)
    
    elif view_mode == "Group of Hosts":
        with db.session() as session:
            # Define filterable columns (exclude technical columns like IDs)
            filterable_columns = [
                'hostname', 'ip_address', 'platform_os', 'role', 'manufacturer', 
                'model', 'status', 'site', 'location', 'is_vm', 'cluster', 
                'dns_name', 'prefix_name', 'vlan_name', 'vlan_display'
            ]
            
            selected_filters = {}
            
            # Add a separate netbox tags filter section
            st.sidebar.subheader("NetBox Tags")
            use_tag_filter = st.sidebar.checkbox("Filter by NetBox Tags")
            
            tag_filter_operator = "AND"
            selected_tags = []
            
            if use_tag_filter:
                # Get all available tags from the database
                all_tags = session.query(NetBoxTag.id, NetBoxTag.name, NetBoxTag.color).all()
                
                # Allow user to select multiple tags
                tag_filter_operator = st.sidebar.radio(
                    "Tag filter operator",
                    options=["AND", "OR"],
                    index=0,
                    help="AND: Hosts must have all selected tags. OR: Hosts with any of the selected tags."
                )
                
                # Create a colorful tag selection interface
                st.sidebar.markdown("Select tags:")
                
                # Create 2 columns for the tags to save space
                tag_cols = st.sidebar.columns(2)
                
                for i, tag in enumerate(all_tags):
                    # Determine which column to place this tag
                    col_idx = i % 2
                    
                    # Create a checkbox with tag name
                    is_selected = tag_cols[col_idx].checkbox(
                        label=tag.name,
                        key=f"tag_sigma_{tag.id}"
                    )
                    
                    # If the tag is selected, customize its appearance and add to selected tags
                    if is_selected:
                        # Display a colored version of the selected tag
                        tag_color = tag.color if tag.color else "#808080"  # Default gray if no color
                        tag_cols[col_idx].markdown(
                            f"<div style='background-color:#{tag_color}; color:black; padding:2px 8px; "
                            f"border-radius:3px; display:inline-block; margin-bottom:8px; font-size:0.8em;'>"
                            f"{tag.name}</div>",
                            unsafe_allow_html=True
                        )
                        selected_tags.append(tag.id)
            
            # Let user select which columns to filter on
            filter_columns = st.sidebar.multiselect(
                "Select columns to filter on",
                options=filterable_columns
            )
            
            # Define operator for combining filters
            filter_operator = st.sidebar.radio(
                "Filter combination operator",
                options=["AND", "OR"],
                index=0,
                help="AND: All conditions must match. OR: Any condition can match."
            )
            
            # For each selected column, show distinct values
            if filter_columns:
                st.sidebar.markdown("---")
                st.sidebar.subheader("Filter Values")
                
                for column in filter_columns:
                    # Get distinct values for the column
                    distinct_values = [
                        str(value[0]) if value[0] is not None else "None" 
                        for value in session.query(getattr(Host, column)).distinct().all()
                    ]
                    
                    # Allow multiple value selection
                    selected_values = st.sidebar.multiselect(
                        f"Select {column} values",
                        options=distinct_values,
                        key=f"filter_sigma_{column}"
                    )
                    
                    if selected_values:
                        # Replace "None" string with actual None if needed
                        processed_values = [None if v == "None" else v for v in selected_values]
                        selected_filters[column] = processed_values
                        
            # Process the filters based on operator
            if selected_filters or (use_tag_filter and selected_tags):
                filter_criteria = {
                    "columns": selected_filters,
                    "operator": filter_operator
                }
                
                # Add tag filtering information if enabled
                if use_tag_filter and selected_tags:
                    filter_criteria["tags"] = {
                        "tag_ids": selected_tags,
                        "operator": tag_filter_operator
                    }
    
    # Create tabs for different dashboard sections
    tab1, tab2, tab3 = st.tabs([
        "Host Coverage", 
        "Rule Analysis", 
        "ATT&CK Coverage", 
    ])
    
    # Tab 1: Host Coverage
    with tab1:
        # Rest of the dashboard content will be implemented below
        
        # Create a placeholder to show filter info
        if view_mode == "Specific Host":
            if selected_host_id:
                with db.session() as session:
                    host = session.query(Host).filter(Host.id == selected_host_id).first()
                    if host:
                        st.info(f"Showing data for: {host.hostname} ({host.ip_address})")
        elif view_mode == "Group of Hosts":
            if filter_criteria:
                filter_desc_parts = []
                
                if "columns" in filter_criteria and filter_criteria["columns"]:
                    filter_desc_parts.append(", ".join([f"{col}: {vals}" for col, vals in filter_criteria["columns"].items()]))
                
                if "tags" in filter_criteria and filter_criteria["tags"]["tag_ids"]:
                    with db.session() as session:
                        tag_names = [tag.name for tag in session.query(NetBoxTag).filter(NetBoxTag.id.in_(filter_criteria["tags"]["tag_ids"])).all()]
                    tag_desc = f"Tags ({filter_criteria['tags']['operator']}): {', '.join(tag_names)}"
                    filter_desc_parts.append(tag_desc)
                
                filter_desc = " | ".join(filter_desc_parts)
                st.info(f"Filtered view: {filter_desc}")
        elif view_mode == "All Enabled Rules":
            st.info("Showing data for all enabled rules")

        # Continue with the dashboard implementation
        col1, col2 = st.columns(2)
        
        with db.session() as session:
            # Host Coverage Percentage
            with col1:
                st.subheader("Host Coverage Percentage")
                
                # Apply filtering based on view mode
                if view_mode == "Specific Host" and selected_host_id:
                    # For a specific host, filter directly by ID
                    host_coverage = SigmaQueries.get_host_coverage_percentage_filtered(session, host_ids=[selected_host_id])
                elif view_mode == "Group of Hosts" and filter_criteria:
                    # For a group of hosts, first get the host IDs matching the filter
                    from app.db.queries.attack import AttackMatrixQueries
                    filtered_host_ids = AttackMatrixQueries.get_filtered_hosts(session, filter_criteria)
                    # Then get coverage for those hosts
                    host_coverage = SigmaQueries.get_host_coverage_percentage_filtered(session, host_ids=filtered_host_ids)
                elif view_mode == "All Enabled Rules":
                    # For all enabled rules view, show potential coverage
                    host_coverage = SigmaQueries.get_host_coverage_percentage_potential(session)
                else:
                    # Default: all hosts
                    host_coverage = SigmaQueries.get_host_coverage_percentage(session)
                
                if host_coverage:
                    # Convert to DataFrame
                    df_host_coverage = pd.DataFrame(
                        host_coverage, 
                        columns=["hostname", "ip_address", "covered_rules_count", "total_rules_count", "coverage_percentage"]
                    )
                    
                    # Create bar chart
                    charts.create_bar_chart(
                        df_host_coverage,
                        "hostname",
                        "coverage_percentage",
                        title="Host Coverage Percentage",
                        x_title="Host",
                        y_title="Coverage (%)",
                        key_prefix="host_coverage"
                    )
                else:
                    st.info("No host coverage data available.")
            
            # Coverage Timeline
            with col2:
                st.subheader("Coverage Timeline")
                
                # Apply filtering based on view mode
                if view_mode == "Specific Host" and selected_host_id:
                    coverage_timeline = SigmaQueries.get_coverage_timeline_filtered(session, host_ids=[selected_host_id])
                elif view_mode == "Group of Hosts" and filter_criteria:
                    from app.db.queries.attack import AttackMatrixQueries
                    filtered_host_ids = AttackMatrixQueries.get_filtered_hosts(session, filter_criteria)
                    coverage_timeline = SigmaQueries.get_coverage_timeline_filtered(session, host_ids=filtered_host_ids)
                else:
                    coverage_timeline = SigmaQueries.get_coverage_timeline(session)
                
                if coverage_timeline:
                    # Convert to DataFrame
                    df_timeline = pd.DataFrame(
                        coverage_timeline,
                        columns=["hostname", "review_date", "covered_rules_count", "total_rules_count", "coverage_percentage"]
                    )
                    
                    # Create line chart
                    charts.create_line_chart(
                        df_timeline,
                        "review_date",
                        "coverage_percentage",
                        color_column="hostname",
                        title="Coverage Timeline",
                        x_title="Review Date",
                        y_title="Coverage (%)",
                        key_prefix="coverage_timeline"
                    )
                else:
                    st.info("No coverage timeline data available.")
        
        # Host Rule Coverage
        with db.session() as session:
            st.subheader("Host Rule Coverage")
            
            # Apply filtering based on view mode
            if view_mode == "Specific Host" and selected_host_id:
                host_rule_coverage = SigmaQueries.get_host_rule_coverage_filtered(session, host_ids=[selected_host_id])
            elif view_mode == "Group of Hosts" and filter_criteria:
                from app.db.queries.attack import AttackMatrixQueries
                filtered_host_ids = AttackMatrixQueries.get_filtered_hosts(session, filter_criteria)
                host_rule_coverage = SigmaQueries.get_host_rule_coverage_filtered(session, host_ids=filtered_host_ids)
            else:
                host_rule_coverage = SigmaQueries.get_host_rule_coverage(session)
            
            if host_rule_coverage:
                # Convert to DataFrame
                df_rule_coverage = pd.DataFrame(
                    host_rule_coverage,
                    columns=["hostname", "ip_address", "covered_rules_count"]
                )
                
                # Display as table
                st.dataframe(
                    df_rule_coverage,
                    column_config={
                        "hostname": "Hostname",
                        "ip_address": "IP Address",
                        "covered_rules_count": st.column_config.NumberColumn(
                            "Covered Rules",
                            help="Number of Sigma rules covered by this host"
                        )
                    },
                    use_container_width=True
                )
            else:
                st.info("No host rule coverage data available.")
        
        # Add universal Rule Compliance Analysis section for all view modes
        st.header("Rule Compliance Analysis")
        
        with st.expander("Rule Compliance Analysis"):
            with db.session() as session:
                # Get the appropriate host IDs based on the view mode
                host_ids = []
                if view_mode == "Specific Host" and selected_host_id:
                    host_ids = [selected_host_id]
                    host_info = session.query(Host.hostname, Host.ip_address).filter(Host.id == selected_host_id).first()
                    if host_info:
                        st.info(f"Showing compliance analysis for: {host_info.hostname} ({host_info.ip_address})")
                elif view_mode == "Group of Hosts" and filter_criteria:
                    from app.db.queries.attack import AttackMatrixQueries
                    host_ids = AttackMatrixQueries.get_filtered_hosts(session, filter_criteria)
                    st.info(f"Showing compliance analysis for {len(host_ids)} hosts matching your filter criteria")
                elif view_mode == "All Enabled Rules":
                    st.info("This view shows potential coverage with all enabled rules")
                    # For this view, we'll show a different analysis
                    all_rules = session.query(SigmaRule).filter(SigmaRule.enabled == True).all()
                    st.metric("Total Enabled Rules", f"{len(all_rules):,}")
                    
                    # Show distribution by severity
                    severity_counts = {}
                    for rule in all_rules:
                        severity = rule.level if rule.level else "unknown"
                        if severity not in severity_counts:
                            severity_counts[severity] = 0
                        severity_counts[severity] += 1
                    
                    # Display severity distribution
                    st.subheader("Rule Severity Distribution")
                    severity_df = pd.DataFrame([
                        {"severity": sev, "count": count} 
                        for sev, count in severity_counts.items()
                    ])
                    
                    # Define color map for severity levels
                    severity_colors = {
                        'critical': '#FF0000',
                        'high': '#FF8C00',
                        'medium': '#FFFF00',
                        'low': '#00FF00',
                        'unknown': '#CCCCCC'
                    }
                    
                    # Create pie chart
                    charts.create_pie_chart(
                        severity_df,
                        "severity",
                        "count",
                        title="Rule Severity Distribution",
                        color_map=severity_colors,
                        key_prefix="severity_dist_rules"
                    )
                    return
                else:
                    # Get all host IDs for "All Hosts" view
                    host_ids = [h.id for h in session.query(Host.id).all()]
                    st.info(f"Showing compliance analysis for all {len(host_ids)} hosts")
                
                if not host_ids:
                    st.warning("No hosts found matching the selected criteria.")
                    return
                
                # Create columns for metrics
                metric_cols = st.columns(3)
                
                # For multiple hosts, we need to calculate aggregate metrics
                total_compliant_rules = 0
                total_missing_rules = 0
                total_rules = 0
                
                # Process each host
                for host_id in host_ids:
                    # Get compliant and non-compliant rules
                    compliant_rules = HostQueries.get_host_compliant_noncompliant_rules_universal(
                        session=session, 
                        host_id=host_id,
                        compliant=True
                    )
                    
                    missing_rules = HostQueries.get_host_compliant_noncompliant_rules_universal(
                        session=session,
                        host_id=host_id,
                        compliant=False
                    )
                    
                    # Accumulate metrics
                    total_compliant_rules += len(compliant_rules)
                    total_missing_rules += len(missing_rules)
                    total_rules += len(compliant_rules) + len(missing_rules)
                
                # Calculate average compliance rate
                avg_compliance_rate = (total_compliant_rules / total_rules * 100) if total_rules > 0 else 0
                
                # Display metrics with big numbers
                with metric_cols[0]:
                    st.metric(
                        label="Compliant Rules",
                        value=f"{total_compliant_rules:,}",
                        delta=f"{avg_compliance_rate:.1f}% of total"
                    )
                
                with metric_cols[1]:
                    st.metric(
                        label="Missing Rules", 
                        value=f"{total_missing_rules:,}",
                        delta=f"{100-avg_compliance_rate:.1f}% of total",
                        delta_color="inverse"
                    )
                with metric_cols[2]:
                    st.metric(
                        label="Total Rules",
                        value=f"{total_rules:,}"
                    )
                
                # For single host view, show detailed rule analysis
                if view_mode == "Specific Host" and selected_host_id:
                    host = session.query(Host).filter(Host.id == selected_host_id).first()
                    if host:
                        # Display rule details
                        rule_cols = st.columns(3)
                        
                        with rule_cols[0]:
                            st.subheader("Unnecessary Log Channels")
                            
                            st.info("The following log channels are unnecessary on this host - showing enabled Windows Event Log Channels that are not covered by any defined Sigma Rule.")
                            
                            unnecessary_log_channels = HostQueries.get_host_unnecessary_log_channels(session, selected_host_id)
                            with st.expander(f"Unnecessary Log Channels"):
                                for log_source in unnecessary_log_channels:
                                    _TEXT = f"- **{log_source[0]}**" if log_source[1] == None else f"- **{log_source[0]}** (EventID: {log_source[1]})"
                                    st.markdown(_TEXT)
                        
                        with rule_cols[1]:
                            st.subheader("Compliant Rules")
                            
                            st.info("The following rules are compliant on this host - showing enabled Windows Event Log Channels in the `winlogbeat.yml` file.")
                            
                            # Get compliant rules for this specific host
                            compliant_rules = HostQueries.get_host_compliant_noncompliant_rules_universal(
                                session=session, 
                                host_id=selected_host_id,
                                compliant=True
                            )
                            
                            # Group compliant rules by log source and event ID
                            grouped_rules = {}
                            for rule in compliant_rules:
                                # Extract rule_id, rule_name, category, platform, severity, log_source, event_id
                                # rule[5] is log_source, rule[6] is event_id
                                log_source = rule[5] or "Unknown"
                                event_id = rule[6]
                                
                                if log_source not in grouped_rules:
                                    grouped_rules[log_source] = {}
                                
                                if event_id not in grouped_rules[log_source]:
                                    grouped_rules[log_source][event_id] = []
                                
                                # Add rule with format [SEV:{severity}] {rule_name} with color based on severity
                                severity = rule[4].lower() if rule[4] is not None else "unknown"
                                
                                if severity == 'low':
                                    color = '#007BFF'
                                elif severity == 'medium':
                                    color = '#FFC107' 
                                elif severity == 'high':
                                    color = '#DC3545'
                                else:
                                    color = '#17A2B8'
                                
                                grouped_rules[log_source][event_id].append(f"<span style='color:{color}'>[SEV:{rule[4]}]</span> {rule[1]}")
                            
                            # Display using expanders for each log source
                            if grouped_rules:
                                for log_source, event_ids in grouped_rules.items():
                                    with st.expander(f"{log_source}"):
                                        for event_id, rule_names in event_ids.items():
                                            # Instead of a nested expander, use bold formatting for event IDs
                                            if event_id is not None:
                                                st.markdown(f"**EventID: {event_id}**")
                                                for rule_name in rule_names:
                                                    st.markdown(f"- {rule_name}", unsafe_allow_html=True)
                                                # Add a separator between event IDs
                                                if len(event_ids) > 1:
                                                    st.markdown("---")
                                            else:
                                                # If no event ID, display rules directly
                                                for rule_name in rule_names:
                                                    st.markdown(f"- {rule_name}", unsafe_allow_html=True)
                            else:
                                st.error("No compliant rules found!")
                            
                        with rule_cols[2]:
                            st.subheader("Non-Compliant Rules")
                            
                            st.error("To reach a **100% rule coverage**, the following Event Log Channels and respective Event IDs needs to be enabled in the `winlogbeat.yml` on the host.")
                            
                            # Get missing rules for this specific host
                            missing_rules = HostQueries.get_host_compliant_noncompliant_rules_universal(
                                session=session,
                                host_id=selected_host_id,
                                compliant=False
                            )
                            
                            # Group missing rules by log source and event ID
                            grouped_rules = {}
                            for rule in missing_rules:
                                # Extract rule_id, rule_name, category, platform, severity, log_source, event_id
                                # rule[5] is log_source, rule[6] is event_id
                                log_source = rule[5] or "Unknown"
                                event_id = rule[6]
                                
                                if log_source not in grouped_rules:
                                    grouped_rules[log_source] = {}
                                
                                if event_id not in grouped_rules[log_source]:
                                    grouped_rules[log_source][event_id] = []
                                
                                # Add rule with format [SEV:{severity}] {rule_name} with color based on severity
                                
                                severity = rule[4].lower() if rule[4] is not None else "unknown"
                                
                                if severity == 'low':
                                    color = '#007BFF'
                                elif severity == 'medium':
                                    color = '#FFC107' 
                                elif severity == 'high':
                                    color = '#DC3545'
                                else:
                                    color = '#17A2B8'
                                    
                                grouped_rules[log_source][event_id].append(f"<span style='color:{color}'>[SEV:{rule[4]}]</span> {rule[1]}")
                            
                            # Display using expanders for each log source
                            if grouped_rules:
                                for log_source, event_ids in grouped_rules.items():
                                    with st.expander(f"{log_source}"):
                                        for event_id, rule_names in event_ids.items():
                                            # Instead of a nested expander, use bold formatting for event IDs
                                            if event_id is not None:
                                                st.markdown(f"**EventID: {event_id}**")
                                                for rule_name in rule_names:
                                                    st.markdown(f"- {rule_name}", unsafe_allow_html=True)
                                                # Add a separator between event IDs
                                                if len(event_ids) > 1:
                                                    st.markdown("---")
                                            else:
                                                # If no event ID, display rules directly
                                                for rule_name in rule_names:
                                                    st.markdown(f"- {rule_name}", unsafe_allow_html=True)
                            else:
                                st.subheader("This host is fully compliant!")
                else:
                    # For multiple hosts view, show summary statistics
                    st.subheader("Compliance Summary by Host")
                    
                    # Get compliance data for all selected hosts
                    host_compliance_data = []
                    for host_id in host_ids:
                        host_info = session.query(Host.hostname, Host.ip_address).filter(Host.id == host_id).first()
                        if not host_info:
                            continue
                            
                        compliant_rules = HostQueries.get_host_compliant_noncompliant_rules_universal(
                            session=session, 
                            host_id=host_id,
                            compliant=True
                        )
                        
                        missing_rules = HostQueries.get_host_compliant_noncompliant_rules_universal(
                            session=session,
                            host_id=host_id,
                            compliant=False
                        )
                        
                        num_compliant = len(compliant_rules)
                        num_missing = len(missing_rules)
                        total = num_compliant + num_missing
                        compliance_rate = (num_compliant / total * 100) if total > 0 else 0
                        
                        host_compliance_data.append({
                            "hostname": host_info.hostname,
                            "ip_address": host_info.ip_address,
                            "compliant_rules": num_compliant,
                            "missing_rules": num_missing,
                            "total_rules": total,
                            "compliance_rate": compliance_rate
                        })
                    
                    # Convert to DataFrame and display
                    if host_compliance_data:
                        df_compliance = pd.DataFrame(host_compliance_data)
                        
                        # Create bar chart of compliance rates
                        charts.create_bar_chart(
                            df_compliance,
                            "hostname",
                            "compliance_rate",
                            title="Host Compliance Rates",
                            x_title="Host",
                            y_title="Compliance Rate (%)",
                            key_prefix="host_compliance_rates"
                        )
                        
                        # Display as table with details
                        st.dataframe(
                            df_compliance,
                            column_config={
                                "hostname": "Host",
                                "ip_address": "IP Address",
                                "compliant_rules": st.column_config.NumberColumn(
                                    "Compliant Rules",
                                    help="Number of rules that are compliant on this host"
                                ),
                                "missing_rules": st.column_config.NumberColumn(
                                    "Missing Rules",
                                    help="Number of rules that are missing on this host"
                                ),
                                "total_rules": st.column_config.NumberColumn(
                                    "Total Rules",
                                    help="Total number of rules applicable to this host"
                                ),
                                "compliance_rate": st.column_config.ProgressColumn(
                                    "Compliance Rate",
                                    format="%.2f%%",
                                    min_value=0,
                                    max_value=100
                                )
                            },
                            use_container_width=True
                        )
                    else:
                        st.warning("No compliance data available for the selected hosts.")
        
        # Additional Host Coverage Analysis - only show if not specific host view
        if view_mode != "Specific Host":
            st.header("Additional Host Coverage Analysis")
        
        # Create 2 columns for the first row of charts
        col1, col2 = st.columns(2)
        
        with db.session() as session:
            # Platform Coverage Analysis
            with col1:
                st.subheader("Coverage by Platform")
                
                # Apply filtering based on view mode
                if view_mode == "Group of Hosts" and filter_criteria:
                    from app.db.queries.attack import AttackMatrixQueries
                    filtered_host_ids = AttackMatrixQueries.get_filtered_hosts(session, filter_criteria)
                    platform_coverage = AdditionalHostCoverage.get_host_coverage_by_platform_filtered(
                        session, host_ids=filtered_host_ids
                    )
                else:
                    platform_coverage = AdditionalHostCoverage.get_host_coverage_by_platform(session)
                
                if platform_coverage:
                    df_platform = pd.DataFrame(
                        platform_coverage,
                        columns=["platform_os", "host_count", "avg_coverage_percentage", 
                                "min_coverage_percentage", "max_coverage_percentage", 
                                "stddev_coverage_percentage"]
                    )
                    
                    # Bar chart with error bars for min/max range
                    charts.create_bar_chart(
                        df_platform,
                        "platform_os",
                        "avg_coverage_percentage",
                        title="Coverage by Platform OS",
                        x_title="Platform",
                        y_title="Avg Coverage (%)",
                        key_prefix="platform_coverage"
                    )
                    
                    # Display as table for detailed view
                    st.dataframe(
                        df_platform,
                        column_config={
                            "platform_os": "Platform",
                            "host_count": "Host Count",
                            "avg_coverage_percentage": st.column_config.NumberColumn(
                                "Avg Coverage %",
                                format="%.2f"
                            ),
                            "min_coverage_percentage": st.column_config.NumberColumn(
                                "Min Coverage %",
                                format="%.2f"
                            ),
                            "max_coverage_percentage": st.column_config.NumberColumn(
                                "Max Coverage %",
                                format="%.2f"
                            ),
                            "stddev_coverage_percentage": st.column_config.NumberColumn(
                                "StdDev",
                                format="%.2f"
                            )
                        },
                        use_container_width=True
                    )
                else:
                    st.info("No platform coverage data available.")
            
            # Tag Coverage Analysis
            with col2:
                st.subheader("Coverage by Tag")
                
                # Apply filtering based on view mode
                if view_mode == "Group of Hosts" and filter_criteria:
                    from app.db.queries.attack import AttackMatrixQueries
                    filtered_host_ids = AttackMatrixQueries.get_filtered_hosts(session, filter_criteria)
                    tag_coverage = AdditionalHostCoverage.get_host_coverage_by_tag_filtered(
                        session, host_ids=filtered_host_ids
                    )
                else:
                    tag_coverage = AdditionalHostCoverage.get_host_coverage_by_tag(session)
                
                if tag_coverage:
                    df_tags = pd.DataFrame(
                        tag_coverage,
                        columns=["tag_name", "hosts_count", "avg_coverage_percentage"]
                    )
                    
                    charts.create_bar_chart(
                        df_tags,
                        "tag_name",
                        "avg_coverage_percentage",
                        title="Coverage by Host Tag",
                        x_title="Tag",
                        y_title="Avg Coverage (%)",
                        key_prefix="tag_coverage"
                    )
                else:
                    st.info("No tag coverage data available.")
        
            # Create 2 columns for the second row of charts
            col1, col2 = st.columns(2)
            
            with db.session() as session:
                # Outlier Analysis
                with col1:
                    st.subheader("Coverage Outlier Analysis")
                    
                    # Apply filtering based on view mode
                    if view_mode == "Group of Hosts" and filter_criteria:
                        from app.db.queries.attack import AttackMatrixQueries
                        filtered_host_ids = AttackMatrixQueries.get_filtered_hosts(session, filter_criteria)
                        outliers = AdditionalHostCoverage.get_outlier_analysis_filtered(
                            session, host_ids=filtered_host_ids
                        )
                    else:
                        outliers = AdditionalHostCoverage.get_outlier_analysis(session)
                    
                    if outliers:
                        df_outliers = pd.DataFrame(
                            outliers,
                            columns=["hostname", "site", "platform_os", "covered_rules", 
                                    "avg_coverage", "stddev_coverage", "z_score", 
                                    "performance_category"]
                        )
                        
                        # Add a categorical color map for performance categories
                        color_map = {
                            'Severely Below Average': '#FF0000',
                            'Below Average': '#FFA500',
                            'Average': '#FFFF00',
                            'Above Average': '#90EE90',
                            'Exceptionally Above Average': '#00FF00'
                        }
                        
                        # Create scatter plot of z-scores
                        charts.create_scatter_chart(
                            df_outliers,
                            "hostname",
                            "z_score",
                            color_column="performance_category",
                            size_column="covered_rules",
                            hover_data=["site", "platform_os", "covered_rules", "avg_coverage"],
                            title="Coverage Outlier Analysis",
                            x_title="Host",
                            y_title="Z-Score",
                            key_prefix="outlier_analysis",
                            color_map=color_map
                        )
                        
                        # Display top 10 outliers as a table
                        st.caption("Top Outliers")
                        st.dataframe(
                            df_outliers.head(10),
                            column_config={
                                "hostname": "Host",
                                "site": "Site",
                                "platform_os": "Platform",
                                "covered_rules": "Covered Rules",
                                "avg_coverage": st.column_config.NumberColumn(
                                    "Site Avg",
                                    format="%.2f"
                                ),
                                "z_score": st.column_config.NumberColumn(
                                    "Z-Score",
                                    format="%.2f"
                                ),
                                "performance_category": "Performance"
                            },
                            use_container_width=True
                        )
                    else:
                        st.info("No outlier analysis data available.")
                
                # Host Vulnerability Exposure
                with col2:
                    st.subheader("Critical Vulnerability Exposure")
                    
                    # Apply filtering based on view mode
                    if view_mode == "Group of Hosts" and filter_criteria:
                        from app.db.queries.attack import AttackMatrixQueries
                        filtered_host_ids = AttackMatrixQueries.get_filtered_hosts(session, filter_criteria)
                        vulnerability = AdditionalHostCoverage.get_host_vulnerability_exposure_filtered(
                            session, host_ids=filtered_host_ids
                        )
                        # For filtered version, create dataframe with proper columns 
                        if vulnerability:
                            df_vuln = pd.DataFrame(
                                vulnerability,
                                columns=["host_id", "hostname", "ip_address", "critical_rules_missing", 
                                        "missing_critical_rules"]
                            )
                            # Drop the host_id column as it's not needed for display
                            df_vuln = df_vuln.drop(columns=["host_id"])
                    else:
                        vulnerability = AdditionalHostCoverage.get_host_vulnerability_exposure(session)
                        # For regular version, create dataframe with standard columns
                        if vulnerability:
                            df_vuln = pd.DataFrame(
                                vulnerability,
                                columns=["hostname", "ip_address", "missing_critical_rules", 
                                        "critical_rules_missing"]
                            )
                    
                    if vulnerability:
                        # Create bar chart of missing critical rules
                        charts.create_bar_chart(
                            df_vuln,
                            "hostname",
                            "missing_critical_rules",
                            title="Missing Critical/High Rules per Host",
                            x_title="Host",
                            y_title="Missing Rules Count",
                            key_prefix="vulnerability_exposure"
                        )
                        
                        # Display as table with details
                        st.caption("Hosts with missing critical/high severity rules")
                        st.dataframe(
                            df_vuln,
                            column_config={
                                "hostname": "Host",
                                "ip_address": "IP Address",
                                "missing_critical_rules": st.column_config.NumberColumn(
                                    "Missing Critical Rules",
                                    help="Number of critical/high severity rules not covered"
                                ),
                                "critical_rules_missing": "Missing Rules List"
                            },
                            use_container_width=True
                        )
                    else:
                        st.info("No vulnerability exposure data available.")
            
            # Create 2 columns for the third row of charts  
            col1, col2 = st.columns(2)
            
            with db.session() as session:
                # Severity Level Coverage
                with col1:
                    st.subheader("Coverage by Severity Level")
                    
                    # Apply filtering based on view mode
                    if view_mode == "Group of Hosts" and filter_criteria:
                        from app.db.queries.attack import AttackMatrixQueries
                        filtered_host_ids = AttackMatrixQueries.get_filtered_hosts(session, filter_criteria)
                        severity_coverage = AdditionalHostCoverage.get_host_coverage_by_severity_level_filtered(
                            session, host_ids=filtered_host_ids
                        )
                    else:
                        severity_coverage = AdditionalHostCoverage.get_host_coverage_by_severity_level(session)
                    
                    if severity_coverage:
                        df_severity_cov = pd.DataFrame(
                            severity_coverage,
                            columns=["hostname", "site", "level", "covered_rules_count", 
                                    "total_rules_by_level", "coverage_percentage"]
                        )
                        
                        # Create grouped bar chart by severity level
                        # First create a pivot table for better visualization
                        pivot_df = df_severity_cov.pivot_table(
                            index="hostname",
                            columns="level",
                            values="coverage_percentage",
                            aggfunc="mean"
                        ).reset_index()
                        
                        # Limit to top 10 hosts for readability if many hosts
                        if len(pivot_df) > 10:
                            pivot_df = pivot_df.head(10)
                        
                        # Create a heatmap
                        melt_df = pivot_df.melt(id_vars="hostname", var_name="level", value_name="coverage_percentage")
                        charts.create_heatmap(
                            melt_df,
                            "hostname",
                            "level",
                            "coverage_percentage",
                            title="Host Coverage by Severity Level",
                            x_title="Host",
                            y_title="Severity Level",
                            color_scale="RdYlGn",
                            key_prefix="severity_coverage"
                        )
                    else:
                        st.info("No severity level coverage data available.")
                
                # Gap Analysis
                with col2:
                    st.subheader("Coverage Gap Analysis")
                    
                    # Apply filtering based on view mode
                    if view_mode == "Group of Hosts" and filter_criteria:
                        from app.db.queries.attack import AttackMatrixQueries
                        filtered_host_ids = AttackMatrixQueries.get_filtered_hosts(session, filter_criteria)
                        gap_analysis = AdditionalHostCoverage.get_gap_analysis_filtered(
                            session, host_ids=filtered_host_ids
                        )
                    else:
                        gap_analysis = AdditionalHostCoverage.get_gap_analysis(session)
                    
                    if gap_analysis:
                        df_gaps = pd.DataFrame(
                            gap_analysis,
                            columns=["hostname", "ip_address", "platform_os", 
                                    "missing_rules_count", "gap_percentage"]
                        )
                        
                        # Create bar chart of gap percentage
                        charts.create_bar_chart(
                            df_gaps.head(10),  # Show only top 10 gaps for readability
                            "hostname",
                            "gap_percentage",
                            title="Top 10 Coverage Gaps",
                            x_title="Host",
                            y_title="Gap Percentage (%)",
                            key_prefix="gap_analysis"
                        )
                        
                        # Display as table with details
                        st.dataframe(
                            df_gaps.head(10),
                            column_config={
                                "hostname": "Host",
                                "ip_address": "IP Address",
                                "platform_os": "Platform",
                                "missing_rules_count": st.column_config.NumberColumn(
                                    "Missing Rules Count",
                                    help="Number of rules not covered by this host"
                                ),
                                "gap_percentage": st.column_config.NumberColumn(
                                    "Gap Percentage (%)",
                                    format="%.2f",
                                    help="Percentage of rules not covered by this host"
                                )
                            },
                            use_container_width=True
                        )
                    else:
                        st.info("No gap analysis data available.")

    
    
    # Tab 2: Rule Analysis
    with tab2:
        col1, col2 = st.columns(2)
        
        with db.session() as session:
            # Rule Severity Distribution
            with col1:
                st.subheader("Rule Severity Distribution")
                
                # Apply filtering based on view mode
                if view_mode == "Specific Host" and selected_host_id:
                    severity_distribution = SigmaQueries.get_rule_severity_distribution_for_host(
                        session, host_id=selected_host_id
                    )
                elif view_mode == "Group of Hosts" and filter_criteria:
                    from app.db.queries.attack import AttackMatrixQueries
                    filtered_host_ids = AttackMatrixQueries.get_filtered_hosts(session, filter_criteria)
                    severity_distribution = SigmaQueries.get_rule_severity_distribution_for_hosts(
                        session, host_ids=filtered_host_ids
                    )
                else:
                    severity_distribution = SigmaQueries.get_rule_severity_distribution(session)
                
                if severity_distribution:
                    # Convert to DataFrame
                    df_severity = pd.DataFrame(
                        severity_distribution,
                        columns=["severity_level", "rule_count"]
                    )
                    
                    # Define color map for severity levels
                    severity_colors = {
                        'critical': '#FF0000',
                        'high': '#FF8C00',
                        'medium': '#FFFF00',
                        'low': '#00FF00',
                        'undefined': '#CCCCCC'
                    }
                    
                    # Create pie chart
                    charts.create_pie_chart(
                        df_severity,
                        "severity_level",
                        "rule_count",
                        title="Rule Severity Distribution",
                        color_map=severity_colors,
                        key_prefix="severity_dist"
                    )
                else:
                    st.info("No rule severity data available.")
            
            # Top/Bottom Covered Rules
            with col2:
                st.subheader("Top/Bottom Covered Rules")
                
                # Apply filtering based on view mode
                if view_mode == "Group of Hosts" and filter_criteria:
                    from app.db.queries.attack import AttackMatrixQueries
                    filtered_host_ids = AttackMatrixQueries.get_filtered_hosts(session, filter_criteria)
                    covered_rules = SigmaQueries.get_top_bottom_covered_rules_filtered(
                        session, host_ids=filtered_host_ids
                    )
                else:
                    covered_rules = SigmaQueries.get_top_bottom_covered_rules(session)
                
                if covered_rules:
                    # Convert to DataFrame
                    df_covered_rules = pd.DataFrame(
                        covered_rules,
                        columns=["rule_name", "sigma_rule_id", "compliant_hosts_count", "category"]
                    )
                    
                    # Create bar chart
                    charts.create_bar_chart(
                        df_covered_rules,
                        "rule_name",
                        "compliant_hosts_count",
                        color_column="category",
                        title="Top/Bottom Covered Rules",
                        x_title="Rule Name",
                        y_title="Host Count",
                        key_prefix="top_bottom_rules"
                    )
                else:
                    st.info("No rule coverage data available.")
                    
            with st.container():
                st.subheader("No Rules by Windows Log Channel")
                
                # Windows log channels used by rules - no filtering needed as this is global data
                no_rules_by_win_log_channel = SigmaQueries.get_no_rules_by_win_log_channel(session)
                if no_rules_by_win_log_channel:
                    df_no_rules_by_win_log_channel = pd.DataFrame(
                        no_rules_by_win_log_channel, 
                        columns=["windows_event_channel", "sigma_log_source", "rule_count"]
                    )
                            
                    charts.create_bar_chart(
                        df_no_rules_by_win_log_channel,
                        "windows_event_channel",
                        "rule_count",
                        title="No Rules by Windows Log Channel",
                        x_title="Windows Log Channel",
                        y_title="Rule Count"
                    )
                else:
                    st.info("No Windows log channel data available.")
    
    # Tab 3: MITRE Coverage
    with tab3:
        col1, col2 = st.columns(2)
        
        with db.session() as session:
            # MITRE Tactic Distribution
            with col1:
                st.subheader("MITRE Tactic Distribution")
                
                # Apply filtering based on view mode
                if view_mode == "Specific Host" and selected_host_id:
                    tactic_distribution = SigmaQueries.get_mitre_tactic_distribution_for_host(
                        session, host_id=selected_host_id
                    )
                elif view_mode == "Group of Hosts" and filter_criteria:
                    from app.db.queries.attack import AttackMatrixQueries
                    filtered_host_ids = AttackMatrixQueries.get_filtered_hosts(session, filter_criteria)
                    tactic_distribution = SigmaQueries.get_mitre_tactic_distribution_for_hosts(
                        session, host_ids=filtered_host_ids
                    )
                else:
                    tactic_distribution = SigmaQueries.get_mitre_tactic_distribution(session)
                
                if tactic_distribution:
                    # Convert to DataFrame
                    df_tactics = pd.DataFrame(
                        tactic_distribution,
                        columns=["tactic_name", "tactic_id", "rule_count"]
                    )
                    
                    # Create radar chart
                    charts.create_radar_chart(
                        df_tactics,
                        "tactic_name", 
                        ["rule_count"],
                        title="MITRE Tactic Distribution",
                        key_prefix="tactic_dist"
                    )
                else:
                    st.info("No MITRE tactic distribution data available.")
            
            # Technique Coverage Ratio
            with col2:
                st.subheader("Technique Coverage Ratio")
                
                # Apply filtering based on view mode
                if view_mode == "Specific Host" and selected_host_id:
                    technique_coverage = SigmaQueries.get_technique_coverage_ratio_for_host(
                        session, host_id=selected_host_id
                    )
                elif view_mode == "Group of Hosts" and filter_criteria:
                    from app.db.queries.attack import AttackMatrixQueries
                    filtered_host_ids = AttackMatrixQueries.get_filtered_hosts(session, filter_criteria)
                    technique_coverage = SigmaQueries.get_technique_coverage_ratio_for_hosts(
                        session, host_ids=filtered_host_ids
                    )
                else:
                    technique_coverage = SigmaQueries.get_technique_coverage_ratio(session)
                
                if technique_coverage:
                    # Convert to DataFrame
                    df_techniques = pd.DataFrame(
                        technique_coverage,
                        columns=["technique_code", "technique_name", "rule_count", "avg_rule_count", "coverage_ratio"]
                    )
                    
                    # Create scatter chart
                    charts.create_scatter_chart(
                        df_techniques,
                        "technique_name",
                        "coverage_ratio",
                        size_column="rule_count",
                        hover_name="technique_code",
                        hover_data=["rule_count", "avg_rule_count"],
                        title="Rule-to-Technique Coverage Ratio",
                        x_title="Technique",
                        y_title="Coverage Ratio (higher = more rules)",
                        key_prefix="technique_ratio"
                    )
                else:
                    st.info("No technique coverage data available.")
        
        # MITRE Tactic Coverage Stats
        with db.session() as session:
            st.subheader("MITRE Tactic Coverage Statistics")
            
            # Apply filtering based on view mode
            if view_mode == "Group of Hosts" and filter_criteria:
                from app.db.queries.attack import AttackMatrixQueries
                filtered_host_ids = AttackMatrixQueries.get_filtered_hosts(session, filter_criteria)
                tactic_stats = SigmaQueries.get_tactic_coverage_stats_filtered(
                    session, host_ids=filtered_host_ids
                )
            else:
                tactic_stats = SigmaQueries.get_tactic_coverage_stats(session)
            
            if tactic_stats:
                # Convert to DataFrame
                df_tactic_stats = pd.DataFrame(
                    tactic_stats,
                    columns=["tactic_name", "tactic_id", "min_coverage_pct", "max_coverage_pct", 
                             "avg_coverage_pct", "stddev_coverage_pct", "host_count", "total_hosts"]
                )
                
                # Create area chart
                charts.create_area_chart(
                    df_tactic_stats,
                    "tactic_name",
                    ["min_coverage_pct", "avg_coverage_pct", "max_coverage_pct", "stddev_coverage_pct"],
                    labels={
                        "min_coverage_pct": "Min Coverage",
                        "avg_coverage_pct": "Avg Coverage",
                        "max_coverage_pct": "Max Coverage",
                        "stddev_coverage_pct": "StdDev Coverage"
                    },
                    title="Tactic Coverage Range Across Hosts",
                    x_title="MITRE Tactic",
                    y_title="Coverage (%)",
                    key_prefix="tactic_range"
                )
                
                # Display standard deviation as a table below
                st.caption("Standard Deviation of Coverage Per Tactic")
                st.dataframe(
                    df_tactic_stats[["tactic_name", "stddev_coverage_pct", "host_count", "total_hosts"]],
                    column_config={
                        "tactic_name": "Tactic Name",
                        "stddev_coverage_pct": st.column_config.NumberColumn(
                            "Coverage StdDev (%)",
                            help="Standard deviation of coverage percentage across hosts"
                        ),
                        "host_count": "Host Count",
                        "total_hosts": "Total Hosts"
                    },
                    use_container_width=True
                )
            else:
                st.info("No tactic coverage statistics available.")
    
    # # Tab 4: Log Source Analysis
    # with tab4:
    #     col1, col2 = st.columns(2)
        
    #     with db.session() as session:
    #         # Configuration Consistency Analysis
    #         with col1:
    #             st.subheader("Configuration Consistency Analysis")
                
    #             # Apply filtering based on view mode
    #             if view_mode == "Group of Hosts" and filter_criteria:
    #                 from app.db.queries.attack import AttackMatrixQueries
    #                 filtered_host_ids = AttackMatrixQueries.get_filtered_hosts(session, filter_criteria)
    #                 config_consistency = SigmaQueries.get_configuration_consistency_filtered(
    #                     session, host_ids=filtered_host_ids
    #                 )
    #             else:
    #                 config_consistency = SigmaQueries.get_configuration_consistency(session)
                
    #             if config_consistency:
    #                 # Convert to DataFrame
    #                 df_consistency = pd.DataFrame(
    #                     config_consistency,
    #                     columns=["site", "sigma_rule_id", "rule_name", "total_hosts_in_site", 
    #                              "compliant_hosts_in_site", "compliance_percentage"]
    #                 )
                    
    #                 # We need to pivot this data for the heatmap
    #                 pivot_df = df_consistency.pivot_table(
    #                     index="site",
    #                     columns="rule_name",
    #                     values="compliance_percentage",
    #                     aggfunc="mean"
    #                 )
                    
    #                 # Only show a subset of rules if there are many
    #                 if pivot_df.shape[1] > 20:
    #                     st.warning(f"Showing only the first 20 rules out of {pivot_df.shape[1]} for readability.")
    #                     pivot_df = pivot_df.iloc[:, :20]
                    
    #                 # Create heatmap
    #                 charts.create_heatmap(
    #                     pivot_df.reset_index().melt(id_vars="site", var_name="rule_name", value_name="compliance_percentage"),
    #                     "rule_name",
    #                     "site",
    #                     "compliance_percentage",
    #                     title="Configuration Consistency by Site",
    #                     x_title="Rule",
    #                     y_title="Site",
    #                     color_scale="RdYlGn",
    #                     key_prefix="config_consistency"
    #                 )
    #             else:
    #                 st.info("No configuration consistency data available.")
            
    #         # Log Source Category Coverage
    #         with col2:
    #             st.subheader("Log Source Category Coverage")
                
    #             # Apply filtering based on view mode - log source coverage is global, no filtering needed
    #             log_source_coverage = SigmaQueries.get_log_source_coverage(session)
                
    #             if log_source_coverage:
    #                 # Convert to DataFrame
    #                 df_log_sources = pd.DataFrame(
    #                     log_source_coverage,
    #                     columns=["category", "service", "product", "total_rules", 
    #                              "enabled_rules", "enabled_percentage"]
    #                 )
                    
    #                 # Create treemap
    #                 charts.create_treemap(
    #                     df_log_sources,
    #                     ["category", "service", "product"],
    #                     "total_rules",
    #                     color="enabled_percentage",
    #                     hover_data=["enabled_rules", "total_rules"],
    #                     title="Log Source Category Coverage",
    #                     color_continuous_scale="RdYlGn",
    #                     key_prefix="log_source"
    #                 )
    #             else:
    #                 st.info("No log source coverage data available.")


# if __name__ == "__main__":
#     # For development/testing
#     st.set_page_config(page_title="Sigma Rules Dashboard", layout="wide")
#     show_sigma_dashboard()

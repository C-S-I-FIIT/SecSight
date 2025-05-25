import streamlit as st
import json
import os
import base64
import tempfile
import streamlit.components.v1 as components
from sqlalchemy.orm import Session
from app.db.database import Database
from app.db.models import (
    MitreTactic, MitreTechnique, MitreSubtechnique, SigmaRule, Host,
    rule_techniques_map, NetBoxTag, tag_device_rule_map  # Import the NetboxTag and junction table
)
from app.collectors.attack_navigator import MitreNavigatorGenerator
from app.db.queries import AttackMatrixQueries, HostQueries
from typing import Callable, Dict, List, Any, Optional, Union
import time
import math

from loguru import logger


def navigator_template(title: str, description: str, matrix_name: str, matrix_description: str, query_function: Callable, hide_disabled: bool = False, **kwargs):
    # Generate a unique ID for this template instance
    template_id = f"{matrix_name}_{int(time.time())}"
    
    mng = MitreNavigatorGenerator()
    
    st.subheader(title)
    st.info(description)
    screenshot_path = None
    
    with st.spinner("Generating layer..."):
        
        layer_data = mng.generate_navigator_json(matrix_name, matrix_description, query_function, hide_disabled=hide_disabled, **kwargs)
        
        # Create iframe URL with cache-busting query parameter
        full_url = mng.generate_attack_navigator_url(layer_data)
        cache_bust_url = f"{full_url}&t={int(time.time())}"
        
        st.markdown(
            f'<a href="{cache_bust_url}" target="_blank">Open in New Tab</a>',
            unsafe_allow_html=True
        )
        
        # Create a row of buttons for actions
        # Download button using the base64 data

        download_link = mng.get_download_link(layer_data)
        download_filename = f"{matrix_name.replace(' ', '_')}.json"
        
        # Extract the base64 data from the download link
        base64_data = download_link.split('href="data:application/json;base64,')[1].split('"')[0]
        
        with st.expander("ATT&CK Matrix Navigator"):
        
            st.download_button(
                label="Download Layer JSON",
                data=base64.b64decode(base64_data),
                file_name=download_filename,
                mime="application/json",
                key=f"download_{template_id}"
            )
    
    # Open in new tab button - using HTML link instead of JavaScript


    
    # Take screenshot button

        # if st.button("Take Screenshot", key=f"take_screenshot_{template_id}"):
        #     logger.debug("STARTING SCREENSHOT - BUTTON CLICKED")
        #     with st.spinner("Taking screenshot..."):
        #         logger.debug("SPINNER STARTED")
        #         mng.take_screenshot_svg(full_url)
        # #         if path is None:
        #             st.error("Failed to take screenshot")
        #         else:
        #             screenshot_path = path
        
        # # Use a container with a unique ID to force re-rendering
            iframe_container = st.container()
            with iframe_container:
                # The iframe itself - no key parameter as it's not supported
                components.iframe(cache_bust_url, height=1250, scrolling=True)
            
        # screenshot_container = st.container()
        # with screenshot_container:
        #     if screenshot_path:
        #         st.image(screenshot_path)
            
                

def get_host_host_compliant_and_missing_rules(host_id: Optional[int] = None, filter_criteria: Optional[Dict[str, Any]] = None):
    db = Database()
    
    rules = {
        "compliant_rules": {},
        "missing_rules": {},
        "unnecessary_log_channels": {}
    }
    
    host_ids = []
    
    if host_id:
        host_ids = [host_id]
    elif filter_criteria:
        with db.session() as session:
            host_ids = AttackMatrixQueries.get_filtered_hosts(session, filter_criteria)
    else:
        with db.session() as session:
            host_ids = [row.id for row in session.query(Host.id).all()]
    
    
    with db.session() as session:
        
        for _host_id in host_ids:
            compliant_rules = HostQueries.get_host_compliant_noncompliant_rules_universal(session=session, host_id=_host_id, compliant=True)
            rules["compliant_rules"][_host_id] = compliant_rules
            #logger.debug(f"[Host {_host_id}] Compliant rules: {compliant_rules}")
            
            missing_rules = HostQueries.get_host_compliant_noncompliant_rules_universal(session=session, host_id=_host_id, compliant=False)
            rules["missing_rules"][_host_id] = missing_rules
            
            unnecessary_log_channels = HostQueries.get_host_unnecessary_log_channels(session=session, host_id=_host_id)
            rules["unnecessary_log_channels"][_host_id] = unnecessary_log_channels
            #logger.debug(f"[Host {_host_id}] Missing rules: {missing_rules}")
            
    return rules


def show_host_compliant_and_missing_rules_text(rules: Dict[str, Any], hide_disabled: bool = False):
    
    compliant_rules = rules["compliant_rules"]
    missing_rules = rules["missing_rules"]
    
    host_ids = list(compliant_rules.keys())
    
    st.header(f"Compliant and Non-Compliant Rules Analysis")
    
    
    db = Database()
    with db.session() as session:
        
        all_hosts = len(host_ids)
        hosts_w_100_coverage = len([host_id for host_id in host_ids if len(missing_rules[host_id])==0])
        hosts_w_0_coverage = len([host_id for host_id in host_ids if len(compliant_rules[host_id])==0])
        
        # Calculate coverage for each host
        host_coverages = [len(compliant_rules[host_id])/(len(compliant_rules[host_id])+len(missing_rules[host_id])) 
                          if (len(compliant_rules[host_id])+len(missing_rules[host_id])) > 0 else 0 
                          for host_id in host_ids]
        
        # Calculate overall coverage (mean)
        overall_coverage = round(sum(host_coverages)/all_hosts, 1) if all_hosts > 0 else 0
        
        # Calculate standard deviation
        coverage_std_dev = round(math.sqrt(sum([(cov - overall_coverage) ** 2 for cov in host_coverages]) / all_hosts), 1) if all_hosts > 0 else 0
        
        top_metric_cols = st.columns(3)
        with top_metric_cols[0]:
            st.metric(
                label="Number of Hosts",
                value=f"{len(host_ids)}"
            )
        with top_metric_cols[1]:
            st.metric(
                label="Overall coverage",
                value=f"{overall_coverage*100}%",
                delta=f"±{coverage_std_dev*100}% SD"
            )
        with top_metric_cols[2]:
            st.metric(
                label="Number of 100% covered hosts",
                value=f"{hosts_w_100_coverage}",
                delta=f"{hosts_w_100_coverage/all_hosts*100}%" if all_hosts > 0 else "0%"
            )
        # with top_metric_cols[3]:
        #     st.metric(
        #         label="Number of 0% covered hosts",
        #         value=f"{hosts_w_0_coverage}",
        #         delta=f"{hosts_w_0_coverage/all_hosts*100}%" if all_hosts > 0 else "0%"
        #     )
        # with top_metric_cols[4]:
        #     st.metric(
        #         label="Number of hosts with 100% coverage",
        #         value=f"{len(host_ids)}"
        #     )
            
        st.divider()
        for host_id in host_ids:
            host: Host = session.query(Host).filter(Host.id == host_id).first()
            if host is None:
                logger.error(f"[Host {host_id}] Host not found")
                continue
            

            
            with st.expander(f"Host - {host.hostname} ({host.ip_address})"):
                
                    # Create columns for metrics
                # Create columns for metrics
                metric_cols = st.columns(3)
                
                # Calculate metrics
                num_compliant = len(compliant_rules[host_id])
                num_missing = len(missing_rules[host_id])
                total_rules = num_compliant + num_missing
                compliance_rate = (num_compliant / total_rules * 100) if total_rules > 0 else 0
                
                
                
                # Display metrics with big numbers
                st.divider()
                with metric_cols[0]:
                    st.metric(
                        label="Compliant Rules",
                        value=f"{num_compliant:,}",
                        delta=f"{compliance_rate:.1f}% of total"
                    )
                
                with metric_cols[1]:
                    st.metric(
                        label="Missing Rules", 
                        value=f"{num_missing:,}",
                        delta=f"{100-compliance_rate:.1f}% of total",
                        delta_color="inverse"
                    )
                with metric_cols[2]:
                    st.metric(
                        label="Total Rules",
                        value=f"{total_rules:,}"
                    )
                
                compliant_rule_list = compliant_rules[host_id]
                missing_rule_list = missing_rules[host_id]
                
                
                st.text("The following sections are showcasing exact rules that are compliant or non-compliant\
                    on this host with their respective log sources and event IDs.")
                st.warning("""To ensure proper coverage, Windows Log Channels needs to also be enabled on the host via\
                    `wevtutil set-log "<Chanel-Name>" /enabled:true`""")
                st.divider()
                
                cols = st.columns(3)
                
                with cols[0]:
                    st.subheader("Unnecessary Log Channels")
                    
                    st.info("The following log channels are unnecessary on this host - showing enabled\
                        Windows Event Log Channels in the `winlogbeat.yml` file. These chanels are not covered by any defined Sigma Rule in SIEM.")
                    
                    with st.expander(f"Unnecessary Log Channels"):
                        for log_source in rules["unnecessary_log_channels"][host_id]:
                            _TEXT = f"- **{log_source[0]}**" if log_source[1] == None else f"- **{log_source[0]}** (EventID: {log_source[1]})"
                            st.markdown(_TEXT)

                with cols[1]:
                    st.subheader("Compliant Rules")
                    
                    st.info("The following rules are compliant on this host - showing enabled\
                        Windows Event Log Channels in the `winlogbeat.yml` file.")
                    
                    # Group compliant rules by log source and event ID
                    grouped_rules = {}
                    for rule in compliant_rule_list:
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
                    
                with cols[2]:
                    st.subheader("Non-Compliant Rules")
                    
                    st.error("To reach a **100% rule coverage**, the following Event Log Channels and respective Event IDs needs to be enabled in\
                        the `winlogbeat.yml` on the host.")
                    
                    # Group missing rules by log source and event ID
                    grouped_rules = {}
                    for rule in missing_rule_list:
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
                        st.subheader("This host is fully compliant !")


def show_specific_host_page(hide_disabled: bool = False):
    # Get session
    db = Database()
    
    # Create a placeholder for the navigator
    navigator_placeholder = st.empty()
    
    # Use database session as context manager
    with db.session() as session:
        # Get all hosts
        hosts = session.query(Host.id, Host.hostname, Host.ip_address).all()
        
        # Create options for selectbox
        host_options = [f"{host.hostname} ({host.ip_address})" for host in hosts]
        host_id_map = {f"{host.hostname} ({host.ip_address})": host.id for host in hosts}
        
        # Host selection with a key to track changes - move to sidebar
        selected_host = st.sidebar.selectbox(
            "Select Host", 
            options=host_options,
            key=f"host_select"
        )
        selected_host_id = host_id_map.get(selected_host)
        
        # Check if host selection has changed
        if "last_selected_host" not in st.session_state:
            st.session_state.last_selected_host = None
        
        host_changed = st.session_state.last_selected_host != selected_host
        st.session_state.last_selected_host = selected_host
        
        if selected_host_id:
            # Clear the placeholder and rebuild the navigator
            with navigator_placeholder.container():
                # Force rerun when host changes by adding a unique timestamp to matrix name
                unique_suffix = int(time.time())
                
                navigator_template(
                    title=f"MITRE ATT&CK Coverage - {selected_host}",
                    description=f"Percentage of MITRE ATT&CK techniques covered for {selected_host}",
                    matrix_name=f"Host: {selected_host}_{unique_suffix}",
                    matrix_description=f"Coverage information for {selected_host}",
                    query_function=AttackMatrixQueries.get_specific_host_coverage,
                    host_id=selected_host_id
                )
                
            rules = get_host_host_compliant_and_missing_rules(host_id=selected_host_id)
            show_host_compliant_and_missing_rules_text(rules)


def show_host_group_page(hide_disabled: bool = False):
    # Get session
    db = Database()
    
    # Create a placeholder for the matrix
    matrix_placeholder = st.empty()
    
    # Use database session as context manager
    with db.session() as session:
        # Define filterable columns (exclude technical columns like IDs)
        filterable_columns = [
            'hostname', 'ip_address', 'platform_os', 'role', 'manufacturer', 
            'model', 'status', 'site', 'location', 'is_vm', 'cluster', 
            'dns_name', 'prefix_name', 'vlan_name', 'vlan_display'
        ]
        
        # Move filters to sidebar
        st.sidebar.subheader("Configure Filters")
        selected_filters = {}
        
        # Add a separate netbox tags filter section
        st.sidebar.subheader("NetBox Tags")
        use_tag_filter = st.sidebar.checkbox("Filter by NetBox Tags")
        
        tag_filter_operator = "AND"
        selected_tags = []
        
        if use_tag_filter:
            # Get all available tags from the database
            all_tags = session.query(NetBoxTag.id, NetBoxTag.name, NetBoxTag.color).all()
            
            #no_tag_option = NetBoxTag(id=0, name="No Tag", color="#808080")
            #all_tags.append(no_tag_option)
            
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
                
                # Create a colored checkbox with tag name
                tag_color = tag.color if tag.color else "#808080"  # Default gray if no color
                
                # Use markdown for colored tag display
                is_selected = tag_cols[col_idx].checkbox(
                    label=tag.name,
                    key=f"tag_{tag.id}"
                )
                
                # If the tag is selected, customize its appearance and add to selected tags
                if is_selected:
                    # Display a colored version of the selected tag
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
                    key=f"filter_{column}"
                )
                
                if selected_values:
                    # Replace "None" string with actual None if needed
                    processed_values = [None if v == "None" else v for v in selected_values]
                    selected_filters[column] = processed_values
        
        # Generate button in sidebar
        generate_button = st.sidebar.button("Generate MITRE Matrix", key="generate_matrix")
        if generate_button and (selected_filters or (use_tag_filter and selected_tags)):
            # Process the filters based on operator
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
            
            # Use a descriptive name based on the filters
            filter_desc_parts = []
            
            if selected_filters:
                filter_desc_parts.append(", ".join([f"{col}: {vals}" for col, vals in selected_filters.items()]))
            
            if use_tag_filter and selected_tags:
                # Get tag names for display
                tag_names = [tag.name for tag in all_tags if tag.id in selected_tags]
                tag_desc = f"Tags ({tag_filter_operator}): {', '.join(tag_names)}"
                filter_desc_parts.append(tag_desc)
            
            filter_desc = " | ".join(filter_desc_parts)
            
            # Force a refresh by using a unique timestamp in the matrix name
            unique_suffix = int(time.time())
            
            # Clear previous matrix and display new one
            with matrix_placeholder.container():
                navigator_template(
                    title=f"MITRE ATT&CK Coverage - Filtered Hosts",
                    description=f"Coverage for hosts with {filter_desc}",
                    matrix_name=f"Filtered Hosts_{unique_suffix}",
                    matrix_description=f"Host filters: {filter_desc}",
                    query_function=AttackMatrixQueries.get_per_group_of_hosts_coverage,
                    filter_criteria=filter_criteria
                )
                
            rules = get_host_host_compliant_and_missing_rules(filter_criteria=filter_criteria)
            
            show_host_compliant_and_missing_rules_text(rules)
                
        elif generate_button and not (selected_filters or (use_tag_filter and selected_tags)):
            # Show warning if no filters are selected
            st.sidebar.warning("Please select at least one filter (column values or tags) before generating the matrix.")


def show_attack_navigator_page():
    #st.title("ATT&CK Navigator")
    
    # Create placeholders for all views
    all_hosts_placeholder = st.empty()
    all_rules_placeholder = st.empty()
    specific_host_placeholder = st.empty()
    host_group_placeholder = st.empty()
    
    # Navigation in sidebar
    st.sidebar.title("MITRE ATT&CK View Selector")
    
    # Create a radio button for navigation
    page = st.sidebar.radio(
        "Select View",
        ["All Hosts Coverage", "All Enabled Rules", "Specific Host Coverage","Group of Hosts Coverage"]
    )
    
    hide_disabled_checkbox = st.sidebar.checkbox("Hide Disabled Techniques", value=True)
    
    
    # Separator between navigation and filters
    st.sidebar.markdown("---")
    
    if page == "All Hosts Coverage":
        # Show only the all hosts view, hide others
        specific_host_placeholder.empty()
        host_group_placeholder.empty()
        all_rules_placeholder.empty()
        
        with all_hosts_placeholder.container():
            # Generate a unique suffix for matrix name to force refresh
            unique_suffix = int(time.time())
            
            navigator_template(
                title="MITRE ATT&CK Coverage - All Hosts",
                description="Percentage of hosts covered by each MITRE ATT&CK technique",
                matrix_name=f"All Hosts_{unique_suffix}",
                matrix_description="Coverage information from all hosts",
                query_function=AttackMatrixQueries.get_all_hosts_coverage,
                hide_disabled=hide_disabled_checkbox
            )
            
                        
            rules = get_host_host_compliant_and_missing_rules(filter_criteria=None)
            show_host_compliant_and_missing_rules_text(rules)
        
    
    elif page == "Specific Host Coverage":
        # Hide other views
        all_hosts_placeholder.empty()
        host_group_placeholder.empty()
        all_rules_placeholder.empty()
        
        # Show specific host page in its own placeholder
        with specific_host_placeholder.container():
            show_specific_host_page(hide_disabled=hide_disabled_checkbox)

    
    elif page == "Group of Hosts Coverage":
        # Hide other views
        all_hosts_placeholder.empty()
        specific_host_placeholder.empty()
        all_rules_placeholder.empty()
        
        # Show host group page in its own placeholder
        with host_group_placeholder.container():
            show_host_group_page(hide_disabled=hide_disabled_checkbox)
    
    elif page == "All Enabled Rules":
        # Hide other views
        all_hosts_placeholder.empty()
        specific_host_placeholder.empty()
        host_group_placeholder.empty()
        
        with all_rules_placeholder.container():
            # Generate a unique suffix for matrix name to force refresh
            unique_suffix = int(time.time())
            
            navigator_template(
                title="MITRE ATT&CK Coverage - All enabled rules",
                description="Full MITRE ATT&CK Matrix showcasing all enabled rules - Ideal state",
                matrix_name=f"All enabled rules_{unique_suffix}",
                matrix_description="Coverage information from all enabled rules",
                query_function=AttackMatrixQueries.get_all_implemented_rules,
                hide_disabled=hide_disabled_checkbox
            )



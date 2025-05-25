import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from app.db.database import Database
from app.db.queries.thehive import TheHiveQueries


def thehive_page():
    st.title("TheHive Alerts & Cases")
    
    # Create database connection
    db = Database()
    
    # Top metrics - always displayed at the top
    st.header("Metrics")
    with db.session() as session:
        col1, col2, col3 = st.columns(3)
        
        # Display metrics
        open_cases = TheHiveQueries.get_case_counts_by_status(session, status="Open")
        closed_cases = TheHiveQueries.get_case_counts_by_status(session, status="Closed")
        total_alerts = TheHiveQueries.get_alert_count(session)
        avg_resolution_time = TheHiveQueries.get_avg_resolution_time(session)
        
        with col1:
            st.metric("Open Cases", open_cases["count"].iloc[0] if not open_cases.empty else 0)
        
        with col2:
            st.metric("Closed Cases", closed_cases["count"].iloc[0] if not closed_cases.empty else 0)
        
        with col3:
            st.metric("Total Alerts", total_alerts["count"].iloc[0] if not total_alerts.empty else 0)
        
        resolution_time = avg_resolution_time["avg_resolution_time"].iloc[0] if not avg_resolution_time.empty else "N/A"
        st.metric("Avg Resolution Time", resolution_time)
    
    # Add a separator
    st.markdown("---")
    
    # Create tabs for different dashboards
    tab1, tab2, tab3 = st.tabs(["Alerts Dashboard", "Cases Dashboard", "Host Analysis"])
    
    with tab1:
        st.header("Alert Analysis")
        
        # Display all alerts with selection functionality
        st.subheader("All Alerts")
        with db.session() as session:
            alerts_df = TheHiveQueries.get_alerts(session)
            
            if not alerts_df.empty:
                # Ensure no duplicates
                alerts_df = alerts_df.drop_duplicates(subset=['id'])
                
                # Create a unique key for this dataframe
                alert_selection_key = "alert_selection_" + str(hash(tuple(alerts_df.columns)))
                
                # Add a selection column
                alerts_df["select"] = False
                
                # Move the select column to be first
                select_col = alerts_df.pop("select")
                alerts_df.insert(0, "select", select_col)
                
                # Display the dataframe with selection checkboxes
                edited_alerts_df = st.data_editor(
                    alerts_df,
                    column_config={
                        "select": st.column_config.CheckboxColumn(
                            "Select",
                            help="Select alert to view MITRE details",
                            default=False,
                        ),
                        "id": st.column_config.NumberColumn("ID"),
                        "title": st.column_config.TextColumn("Title"),
                        "severity": st.column_config.TextColumn("Severity"),
                        "date": st.column_config.DatetimeColumn("Date"),
                        "source": st.column_config.TextColumn("Source"),
                        "status": st.column_config.TextColumn("Status")
                    },
                    disabled=["id", "title", "description", "severity", "date", "source", "status"],
                    hide_index=True,
                    key=alert_selection_key,
                    use_container_width=True
                )
                
                # Find selected alerts
                selected_alerts = edited_alerts_df[edited_alerts_df["select"] == True]
                
                # Display MITRE details for each selected alert
                if not selected_alerts.empty:
                    st.markdown("### Selected Alert Details")
                    for _, row in selected_alerts.iterrows():
                        alert_id = row["id"]
                        alert_title = row["title"]
                        
                        # Create an expander for each selected alert
                        with st.expander(f"🔍 MITRE ATT&CK details for: {alert_title}", expanded=False):
                            # Add a spinner while loading the details
                            with st.spinner("Loading MITRE ATT&CK details..."):
                                mitre_details = TheHiveQueries.get_mitre_details_for_alert(session, alert_id)
                            
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.markdown(f"**Alert ID:** {alert_id}")
                                st.markdown(f"**Severity:** {row['severity']}")
                                
                            with col2:
                                st.markdown(f"**Date:** {row['date']}")
                                st.markdown(f"**Status:** {row['status']}")
                            
                            st.markdown("---")
                            
                            # Display tactics
                            if mitre_details["tactics"]:
                                with st.expander(f"🎯 MITRE Tactics ({len(mitre_details['tactics'])})", expanded=False):
                                    for tactic in mitre_details["tactics"]:
                                        st.markdown(f"**{tactic['name']}** ({tactic['id']})")
                                        if tactic['reference']:
                                            st.markdown(f"[Reference]({tactic['reference']})")
                                        st.markdown("---")
                            
                            # Display techniques with descriptions
                            if mitre_details["techniques"]:
                                with st.expander(f"⚙️ MITRE Techniques ({len(mitre_details['techniques'])})", expanded=False):
                                    for technique in mitre_details["techniques"]:
                                        with st.expander(f"{technique['name']} ({technique['id']})", expanded=False):
                                            if 'description' in technique:
                                                st.markdown("### Description")
                                                st.markdown(technique['description'])
                                            
                                            if 'platforms' in technique and technique['platforms']:
                                                st.markdown("### Platforms")
                                                st.markdown(", ".join(technique['platforms']))
                                            
                                            if 'detection' in technique and technique['detection']:
                                                st.markdown("### Detection")
                                                st.markdown(technique['detection'])
                                            
                                            if technique.get('reference'):
                                                st.markdown(f"[MITRE ATT&CK Reference]({technique['reference']})")
                            
                            # Display mitigations
                            if mitre_details["mitigations"]:
                                with st.expander(f"🛡️ Mitigations ({len(mitre_details['mitigations'])})", expanded=False):
                                    for mitigation in mitre_details["mitigations"]:
                                        with st.expander(f"{mitigation['name']} ({mitigation['id']})", expanded=False):
                                            st.markdown("### Description")
                                            st.markdown(mitigation['description'])
                                            if mitigation.get('reference'):
                                                st.markdown(f"[MITRE ATT&CK Reference]({mitigation['reference']})")
                            
                            if not any([mitre_details["tactics"], mitre_details["techniques"], mitre_details["mitigations"]]):
                                st.info("No MITRE ATT&CK information available for this alert.")
            else:
                st.info("No alerts available")
        
        # Alert distribution by rules
        st.subheader("Alert Distribution by Rules")
        with db.session() as session:
            alert_by_rules = TheHiveQueries.get_alert_distribution_by_rules(session)
            
            if not alert_by_rules.empty:
                # Add controls for rule display
                st.subheader("Rule Frequency")
                
                # Add a search filter for rule names
                rule_search = st.text_input("Search Rule Names:", "", key="rule_search")
                
                # Filter data based on search
                filtered_rules = alert_by_rules.copy()
                if rule_search:
                    filtered_rules = filtered_rules[
                        filtered_rules['rule_name'].str.contains(rule_search, case=False, na=False)
                    ]
                
                # Show rule count stats
                st.info(f"Showing {len(filtered_rules)} rules out of {len(alert_by_rules)} total rules")
                
                # Filter for number of entries to show
                rule_display_options = ['Top 10', 'Top 20', 'Top 50', 'All']
                rule_display_selection = st.radio(
                    "Display Count:", 
                    rule_display_options,
                    horizontal=True,
                    key="rule_display_count"
                )
                
                # Apply display limit to a copy of filtered_rules
                if rule_display_selection == 'Top 10':
                    display_limit = 10
                elif rule_display_selection == 'Top 20':
                    display_limit = 20
                elif rule_display_selection == 'Top 50':
                    display_limit = 50
                else:  # 'All' option
                    display_limit = len(filtered_rules)
                
                # Sort by count descending and apply the limit
                display_rules = filtered_rules.sort_values('count', ascending=False).head(display_limit)
                
                # Create the bar chart
                if not display_rules.empty:
                    fig = px.bar(
                        display_rules, 
                        x="rule_name", 
                        y="count", 
                        color="count",
                        title=f"Alert Rules ({rule_display_selection}{' - Filtered' if rule_search else ''})",
                        height=500  # Increase height for better visibility
                    )
                    
                    # Improve readability for large number of bars
                    if len(display_rules) > 10:
                        fig.update_layout(
                            xaxis_tickangle=-45  # Angle the labels
                        )
                    
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.warning("No rules match your search criteria")
                
                # Add table view of all rules for reference
                with st.expander("View All Rules in Table Format", expanded=False):
                    # Add a download button for CSV export
                    csv = filtered_rules.to_csv(index=False).encode('utf-8')
                    st.download_button(
                        "Download Rules as CSV",
                        csv,
                        "thehive_rules.csv",
                        "text/csv",
                        key='download-rules-csv'
                    )
                    
                    # Display the dataframe
                    st.dataframe(
                        filtered_rules,
                        column_config={
                            "rule_name": "Rule Name",
                            "count": "Alert Count"
                        },
                        height=300
                    )
            else:
                st.info("No data available for alert distribution by rules")
        
        # Alert distribution by tactic
        st.subheader("Alert Distribution by MITRE Tactic")
        with db.session() as session:
            alert_by_tactic = TheHiveQueries.get_alert_distribution_by_tactic(session)
            if not alert_by_tactic.empty:
                fig = px.pie(alert_by_tactic, values="count", names="tactic_name", 
                            title="Alerts by MITRE Tactic")
                st.plotly_chart(fig, use_container_width=True)
            else:
                st.info("No data available for alert distribution by tactic")
        
        # Most mentioned observables
        st.subheader("Observable Analysis")
        with db.session() as session:
            observables = TheHiveQueries.get_most_common_observables(session)
            
            if not observables.empty:
                # Create two columns for the charts
                col1, col2 = st.columns([1, 2])
                
                with col1:
                    # Show distribution by type
                    type_distribution = observables.groupby("data_type").sum().reset_index()
                    fig = px.pie(type_distribution, values="count", names="data_type", 
                                title="Observables by Type")
                    st.plotly_chart(fig, use_container_width=True)
                
                with col2:
                    # Add controls for observable bar chart
                    st.subheader("Observable Frequency")
                    
                    # Filter by type
                    observable_types = ['All Types'] + sorted(observables['data_type'].unique().tolist())
                    chart_type = st.selectbox(
                        "Filter Chart by Observable Type:", 
                        observable_types,
                        key="chart_type_filter"
                    )
                    
                    # Filter for number of entries to show
                    display_options = ['Top 10', 'Top 20', 'Top 50', 'All']
                    display_selection = st.radio(
                        "Display Count:", 
                        display_options,
                        horizontal=True
                    )
                    
                    # Apply filters to create display data
                    chart_data = observables.copy()
                    if chart_type != 'All Types':
                        chart_data = chart_data[chart_data['data_type'] == chart_type]
                    
                    # Display count of filtered data
                    st.info(f"Showing {len(chart_data)} observables " + 
                            (f"of type '{chart_type}'" if chart_type != 'All Types' else "of all types"))
                    
                    # Apply display limit
                    if display_selection == 'Top 10':
                        display_limit = 10
                    elif display_selection == 'Top 20':
                        display_limit = 20
                    elif display_selection == 'Top 50':
                        display_limit = 50
                    else:  # 'All' option
                        display_limit = len(chart_data)
                    
                    # Sort and limit the data for display
                    chart_data = chart_data.sort_values('count', ascending=False).head(display_limit)
                    
                    # Create the bar chart with all filtered observables
                    if not chart_data.empty:
                        fig = px.bar(
                            chart_data, 
                            x="data", 
                            y="count", 
                            color="data_type",
                            title=f"Observable Frequency ({display_selection}{' by ' + chart_type if chart_type != 'All Types' else ''})",
                            height=500  # Increase height for better visibility with more data
                        )
                        
                        # Improve readability for large number of bars
                        if len(chart_data) > 20:
                            fig.update_layout(
                                xaxis_tickangle=-45  # Angle the labels
                            )
                        
                        st.plotly_chart(fig, use_container_width=True)
                    else:
                        st.warning("No observables match your filter criteria")
                
                # Add a section for all observables in a scrollable table
                st.subheader("All Observables (Scrollable)")
                
                # Add filter options
                observable_types_table = ['All Types'] + sorted(observables['data_type'].unique().tolist())
                selected_type = st.selectbox(
                    "Filter Table by Observable Type:", 
                    observable_types_table,
                    key="table_type_filter"
                )
                
                search_term = st.text_input("Search Observables:", "")
                
                # Filter the dataframe based on selections
                filtered_observables = observables.copy()
                if selected_type != 'All Types':
                    filtered_observables = filtered_observables[filtered_observables['data_type'] == selected_type]
                
                if search_term:
                    filtered_observables = filtered_observables[filtered_observables['data'].str.contains(search_term, case=False, na=False)]
                
                # Show count of filtered observables
                st.info(f"Found {len(filtered_observables)} observables matching your filters")
                
                # Add a download button for CSV export
                csv = filtered_observables.to_csv(index=False).encode('utf-8')
                st.download_button(
                    "Download Filtered Observables as CSV",
                    csv,
                    "thehive_observables.csv",
                    "text/csv",
                    key='download-observables-csv'
                )
                
                # Display the filtered dataframe
                st.dataframe(
                    filtered_observables,
                    column_config={
                        "data_type": "Type",
                        "data": "Value",
                        "count": "Alert Count"
                    },
                    height=400  # Set a fixed height to make it scrollable
                )
            else:
                st.info("No data available for observables")
    
    with tab2:
        st.header("Case Analysis")
        
        # Display all cases with selection functionality
        st.subheader("All Cases")
        with db.session() as session:
            cases_df = TheHiveQueries.get_cases(session)
            
            if not cases_df.empty:
                # Ensure no duplicates
                cases_df = cases_df.drop_duplicates(subset=['id'])
                
                # Create a unique key for this dataframe
                case_selection_key = "case_selection_" + str(hash(tuple(cases_df.columns)))
                
                # Add a selection column
                cases_df["select"] = False
                
                # Move the select column to be first
                select_col = cases_df.pop("select")
                cases_df.insert(0, "select", select_col)
                
                # Display the dataframe with selection checkboxes
                edited_cases_df = st.data_editor(
                    cases_df,
                    column_config={
                        "select": st.column_config.CheckboxColumn(
                            "Select",
                            help="Select case to view MITRE details",
                            default=False,
                        ),
                        "id": st.column_config.NumberColumn("ID"),
                        "title": st.column_config.TextColumn("Title"),
                        "severity": st.column_config.TextColumn("Severity"),
                        "start_date": st.column_config.DatetimeColumn("Start Date"),
                        "end_date": st.column_config.DatetimeColumn("End Date"),
                        "owner": st.column_config.TextColumn("Owner"),
                        "status": st.column_config.TextColumn("Status"),
                        "resolution_status": st.column_config.TextColumn("Resolution")
                    },
                    disabled=["id", "title", "description", "severity", "start_date", "end_date", "owner", "status", "resolution_status"],
                    hide_index=True,
                    key=case_selection_key,
                    use_container_width=True
                )
                
                # Find selected cases
                selected_cases = edited_cases_df[edited_cases_df["select"] == True]
                
                # Display MITRE details for each selected case
                if not selected_cases.empty:
                    st.markdown("### Selected Case Details")
                    for _, row in selected_cases.iterrows():
                        case_id = row["id"]
                        case_title = row["title"]
                        
                        # Create an expander for each selected case
                        with st.expander(f"🔍 MITRE ATT&CK details for: {case_title}", expanded=False):
                            # Add a spinner while loading the details
                            with st.spinner("Loading MITRE ATT&CK details..."):
                                mitre_details = TheHiveQueries.get_mitre_details_for_case(session, case_id)
                            
                            col1, col2 = st.columns(2)
                            
                            with col1:
                                st.markdown(f"**Case ID:** {case_id}")
                                st.markdown(f"**Severity:** {row['severity']}")
                                st.markdown(f"**Owner:** {row['owner']}")
                                
                            with col2:
                                st.markdown(f"**Start Date:** {row['start_date']}")
                                st.markdown(f"**Status:** {row['status']}")
                                if row['end_date']:
                                    st.markdown(f"**End Date:** {row['end_date']}")
                            
                            st.markdown("---")
                            
                            # Display tactics
                            if mitre_details["tactics"]:
                                with st.expander(f"🎯 MITRE Tactics ({len(mitre_details['tactics'])})", expanded=False):
                                    for tactic in mitre_details["tactics"]:
                                        st.markdown(f"**{tactic['name']}** ({tactic['id']})")
                                        if tactic['reference']:
                                            st.markdown(f"[Reference]({tactic['reference']})")
                                        st.markdown("---")
                            
                            # Display techniques with descriptions
                            if mitre_details["techniques"]:
                                with st.expander(f"⚙️ MITRE Techniques ({len(mitre_details['techniques'])})", expanded=False):
                                    for technique in mitre_details["techniques"]:
                                        with st.expander(f"{technique['name']} ({technique['id']})", expanded=False):
                                            if 'description' in technique:
                                                st.markdown("### Description")
                                                st.markdown(technique['description'])
                                            
                                            if 'platforms' in technique and technique['platforms']:
                                                st.markdown("### Platforms")
                                                st.markdown(", ".join(technique['platforms']))
                                            
                                            if 'detection' in technique and technique['detection']:
                                                st.markdown("### Detection")
                                                st.markdown(technique['detection'])
                                            
                                            if technique.get('reference'):
                                                st.markdown(f"[MITRE ATT&CK Reference]({technique['reference']})")
                            
                            # Display mitigations
                            if mitre_details["mitigations"]:
                                with st.expander(f"🛡️ Mitigations ({len(mitre_details['mitigations'])})", expanded=False):
                                    for mitigation in mitre_details["mitigations"]:
                                        with st.expander(f"{mitigation['name']} ({mitigation['id']})", expanded=False):
                                            st.markdown("### Description")
                                            st.markdown(mitigation['description'])
                                            if mitigation.get('reference'):
                                                st.markdown(f"[MITRE ATT&CK Reference]({mitigation['reference']})")
                            
                            if not any([mitre_details["tactics"], mitre_details["techniques"], mitre_details["mitigations"]]):
                                st.info("No MITRE ATT&CK information available for this case.")
            else:
                st.info("No cases available")
        
        # Case distribution by tags
        st.subheader("Case Distribution by Tags")
        with db.session() as session:
            cases_by_tags = TheHiveQueries.get_case_distribution_by_tags(session)
            
            if not cases_by_tags.empty:
                # Add controls for tag display
                tag_display_options = ['Top 10', 'Top 20', 'Top 50', 'All']
                tag_display_selection = st.radio(
                    "Display Count:", 
                    tag_display_options,
                    horizontal=True,
                    key="tag_display_count"
                )
                
                # Apply display limit
                if tag_display_selection == 'Top 10':
                    display_limit = 10
                elif tag_display_selection == 'Top 20':
                    display_limit = 20
                elif tag_display_selection == 'Top 50':
                    display_limit = 50
                else:  # 'All' option
                    display_limit = len(cases_by_tags)
                
                # Sort and limit the data for display
                display_tags = cases_by_tags.head(display_limit)
                
                # Create the bar chart
                fig = px.pie(
                    display_tags, 
                    values="count", 
                    names="tag", 
                    title=f"Case Tags ({tag_display_selection})",
                    height=500
                )
                
                # Improve readability for large number of bars
                if len(display_tags) > 10:
                    fig.update_layout(
                        xaxis_tickangle=-45  # Angle the labels
                    )
                
                st.plotly_chart(fig, use_container_width=True)
                
                # Add table view
                with st.expander("View All Tags in Table Format", expanded=False):
                    st.dataframe(
                        cases_by_tags,
                        column_config={
                            "tag": "Tag",
                            "count": "Case Count"
                        },
                        height=300
                    )
            else:
                st.info("No data available for case distribution by tags")
        
        case_count_col1, case_count_col2 = st.columns(2)
        with case_count_col1:
        # Cases by status
            st.subheader("Case Distribution by Status")
            with db.session() as session:
                cases_by_status = TheHiveQueries.get_case_distribution_by_status(session)
                if not cases_by_status.empty:
                    fig = px.pie(cases_by_status, values="count", names="status", 
                                title="Cases by Status")
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No data available for case distribution by status")
        
        with case_count_col2:
        # Cases by resolution type
            st.subheader("Closed Cases by Resolution Type")
            with db.session() as session:
                cases_by_resolution = TheHiveQueries.get_closed_cases_by_resolution_type(session)
                if not cases_by_resolution.empty:
                    fig = px.pie(cases_by_resolution, values="count", names="resolution_status", 
                                title="Closed Cases by Resolution Type")
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No data available for closed cases by resolution type")
        
        case_count_col3, case_count_col4 = st.columns(2)
        with case_count_col3:
            # Cases by assignee
            st.subheader("Cases by Assignee")
            with db.session() as session:
                cases_by_assignee = TheHiveQueries.get_case_distribution_by_assignee(session)
                if not cases_by_assignee.empty:
                    fig = px.pie(cases_by_assignee, values="count", names="owner", 
                                title="Cases by Assignee")
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No data available for cases by assignee")
        
        with case_count_col4:
            # Case distribution by observable count
            st.subheader("Case Distribution by Number of Observables")
            with db.session() as session:
                cases_by_observable_count = TheHiveQueries.get_case_distribution_by_observable_count(session)
                if not cases_by_observable_count.empty:
                    fig = px.histogram(cases_by_observable_count, x="observable_count", 
                                    title="Cases by Observable Count", nbins=10)
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No data available for case distribution by observable count")
    
    with tab3:
        st.header("Host Analysis")
        
        # Filter by host
        with db.session() as session:
            all_hosts = TheHiveQueries.get_all_hosts(session)
            
            if not all_hosts.empty:
                selected_host = st.selectbox(
                    "Select Host for Detailed Analysis:",
                    options=all_hosts["hostname"] + " (" + all_hosts["ip_address"] + ")"
                )
                
                if selected_host:
                    host_ip_with_mask = selected_host.split("(")[1].split(")")[0].strip()
                    # Strip the subnet mask part for matching with artifacts
                    host_ip = host_ip_with_mask.split('/')[0].strip()
                    
                    # Alert distribution by host
                    st.subheader(f"Alerts for Host: {selected_host}")
                    alerts_by_host = TheHiveQueries.get_alerts_by_host_ip(session, host_ip)
                    
                    if not alerts_by_host.empty:
                        # Ensure no duplicates
                        alerts_by_host = alerts_by_host.drop_duplicates(subset=['alert_id'])
                        
                        # Create a unique key for this dataframe
                        host_alert_selection_key = "host_alert_selection_" + str(hash(tuple(alerts_by_host.columns)))
                        
                        # Add a selection column
                        alerts_by_host["select"] = False
                        
                        # Move the select column to be first
                        select_col = alerts_by_host.pop("select")
                        alerts_by_host.insert(0, "select", select_col)
                        
                        # Display the dataframe with selection checkboxes
                        edited_host_alerts_df = st.data_editor(
                            alerts_by_host,
                            column_config={
                                "select": st.column_config.CheckboxColumn(
                                    "Select",
                                    help="Select alert to view MITRE details",
                                    default=False,
                                ),
                                "alert_id": st.column_config.NumberColumn("Alert ID"),
                                "title": st.column_config.TextColumn("Title"),
                                "severity": st.column_config.TextColumn("Severity"),
                                "date": st.column_config.DatetimeColumn("Date"),
                                "source": st.column_config.TextColumn("Source"),
                                "status": st.column_config.TextColumn("Status")
                            },
                            disabled=alerts_by_host.columns.drop("select") if "select" in alerts_by_host.columns else alerts_by_host.columns,
                            hide_index=True,
                            key=host_alert_selection_key,
                            use_container_width=True
                        )
                        
                        # Find selected alerts
                        selected_host_alerts = edited_host_alerts_df[edited_host_alerts_df["select"] == True]
                        
                        # Display MITRE details for each selected alert
                        if not selected_host_alerts.empty:
                            st.markdown("### Selected Host Alert Details")
                            for _, row in selected_host_alerts.iterrows():
                                alert_id = row["alert_id"]
                                alert_title = row["title"]
                                
                                # Create an expander for each selected alert
                                with st.expander(f"🔍 MITRE ATT&CK details for: {alert_title}", expanded=False):
                                    # Add a spinner while loading the details
                                    with st.spinner("Loading MITRE ATT&CK details..."):
                                        mitre_details = TheHiveQueries.get_mitre_details_for_alert(session, alert_id)
                                    
                                    col1, col2 = st.columns(2)
                                    
                                    with col1:
                                        st.markdown(f"**Alert ID:** {alert_id}")
                                        st.markdown(f"**Severity:** {row['severity']}")
                                        
                                    with col2:
                                        st.markdown(f"**Date:** {row['date']}")
                                        st.markdown(f"**Status:** {row['status']}")
                                    
                                    st.markdown("---")
                                    
                                    # Display tactics
                                    if mitre_details["tactics"]:
                                        with st.expander(f"🎯 MITRE Tactics ({len(mitre_details['tactics'])})", expanded=False):
                                            for tactic in mitre_details["tactics"]:
                                                st.markdown(f"**{tactic['name']}** ({tactic['id']})")
                                                if tactic['reference']:
                                                    st.markdown(f"[Reference]({tactic['reference']})")
                                                st.markdown("---")
                                    
                                    data_cols = st.columns(2)
                                    with data_cols[0]:
                                    # Display techniques with descriptions
                                        if mitre_details["techniques"]:
                                            with st.expander(f"⚙️ MITRE Techniques ({len(mitre_details['techniques'])})", expanded=False):
                                                for technique in mitre_details["techniques"]:
                                                    with st.expander(f"{technique['name']} ({technique['id']})", expanded=False):
                                                        if 'description' in technique:
                                                            st.markdown("### Description")
                                                            st.markdown(technique['description'])
                                                        
                                                        if 'platforms' in technique and technique['platforms']:
                                                            st.markdown("### Platforms")
                                                            st.markdown(", ".join(technique['platforms']))
                                                        
                                                        if 'detection' in technique and technique['detection']:
                                                            st.markdown("### Detection")
                                                            st.markdown(technique['detection'])
                                                        
                                                        if technique.get('reference'):
                                                            st.markdown(f"[MITRE ATT&CK Reference]({technique['reference']})")
                                    with data_cols[1]:
                                        # Display mitigations
                                        if mitre_details["mitigations"]:
                                            with st.expander(f"🛡️ Mitigations ({len(mitre_details['mitigations'])})", expanded=False):
                                                for mitigation in mitre_details["mitigations"]:
                                                    with st.expander(f"{mitigation['name']} ({mitigation['id']})", expanded=False):
                                                        st.markdown("### Description")
                                                        st.markdown(mitigation['description'])
                                                        if mitigation.get('reference'):
                                                            st.markdown(f"[MITRE ATT&CK Reference]({mitigation['reference']})")
                                    
                                    if not any([mitre_details["tactics"], mitre_details["techniques"], mitre_details["mitigations"]]):
                                        st.info("No MITRE ATT&CK information available for this alert.")
                    else:
                        st.info(f"No alerts found for host {selected_host}")
                    
                    # Case distribution by host
                    st.subheader(f"Cases for Host: {selected_host}")
                    cases_by_host = TheHiveQueries.get_cases_by_host_ip(session, host_ip)
                    
                    if not cases_by_host.empty:
                        # Ensure no duplicates
                        cases_by_host = cases_by_host.drop_duplicates(subset=['case_id'])
                        
                        # Create a unique key for this dataframe
                        host_case_selection_key = "host_case_selection_" + str(hash(tuple(cases_by_host.columns)))
                        
                        # Add a selection column
                        cases_by_host["select"] = False
                        
                        # Move the select column to be first
                        select_col = cases_by_host.pop("select")
                        cases_by_host.insert(0, "select", select_col)
                        
                        # Display the dataframe with selection checkboxes
                        edited_host_cases_df = st.data_editor(
                            cases_by_host,
                            column_config={
                                "select": st.column_config.CheckboxColumn(
                                    "Select",
                                    help="Select case to view MITRE details",
                                    default=False,
                                ),
                                "case_id": st.column_config.NumberColumn("Case ID"),
                                "case_title": st.column_config.TextColumn("Title"),
                                "case_severity": st.column_config.TextColumn("Severity"),
                                "start_date": st.column_config.DatetimeColumn("Start Date"),
                                "end_date": st.column_config.DatetimeColumn("End Date"),
                                "case_status": st.column_config.TextColumn("Status"),
                                "resolution_status": st.column_config.TextColumn("Resolution")
                            },
                            disabled=cases_by_host.columns.drop("select") if "select" in cases_by_host.columns else cases_by_host.columns,
                            hide_index=True,
                            key=host_case_selection_key,
                            use_container_width=True
                        )
                        
                        # Find selected cases
                        selected_host_cases = edited_host_cases_df[edited_host_cases_df["select"] == True]
                        
                        # Display MITRE details for each selected case
                        if not selected_host_cases.empty:
                            st.markdown("### Selected Host Case Details")
                            for _, row in selected_host_cases.iterrows():
                                case_id = row["case_id"]
                                case_title = row["case_title"]
                                
                                # Create an expander for each selected case
                                with st.expander(f"🔍 MITRE ATT&CK details for: {case_title}", expanded=False):
                                    # Add a spinner while loading the details
                                    with st.spinner("Loading MITRE ATT&CK details..."):
                                        mitre_details = TheHiveQueries.get_mitre_details_for_case(session, case_id)
                                    
                                    col1, col2 = st.columns(2)
                                    
                                    with col1:
                                        st.markdown(f"**Case ID:** {case_id}")
                                        st.markdown(f"**Severity:** {row['case_severity']}")
                                        
                                    with col2:
                                        st.markdown(f"**Start Date:** {row['start_date']}")
                                        st.markdown(f"**Status:** {row['case_status']}")
                                        if row['end_date']:
                                            st.markdown(f"**End Date:** {row['end_date']}")
                                    
                                    st.markdown("---")
                                    
                                    # Display tactics
                                    if mitre_details["tactics"]:
                                        with st.expander(f"🎯 MITRE Tactics ({len(mitre_details['tactics'])})", expanded=False):
                                            for tactic in mitre_details["tactics"]:
                                                st.markdown(f"**{tactic['name']}** ({tactic['id']})")
                                                if tactic['reference']:
                                                    st.markdown(f"[Reference]({tactic['reference']})")
                                                st.markdown("---")
                                    
                                    data_cols = st.columns(2)
                                    with data_cols[0]:
                                    # Display techniques with descriptions
                                        if mitre_details["techniques"]:
                                            with st.expander(f"⚙️ MITRE Techniques ({len(mitre_details['techniques'])})", expanded=False):
                                                for technique in mitre_details["techniques"]:
                                                    with st.expander(f"{technique['name']} ({technique['id']})", expanded=False):
                                                        if 'description' in technique:
                                                            st.markdown("### Description")
                                                            st.markdown(technique['description'])
                                                        
                                                        if 'platforms' in technique and technique['platforms']:
                                                            st.markdown("### Platforms")
                                                            st.markdown(", ".join(technique['platforms']))
                                                        
                                                        if 'detection' in technique and technique['detection']:
                                                            st.markdown("### Detection")
                                                            st.markdown(technique['detection'])
                                                        
                                                        if technique.get('reference'):
                                                            st.markdown(f"[MITRE ATT&CK Reference]({technique['reference']})")
                                    
                                    with data_cols[1]:
                                    # Display mitigations
                                        if mitre_details["mitigations"]:
                                            with st.expander(f"🛡️ Mitigations ({len(mitre_details['mitigations'])})", expanded=False):
                                                for mitigation in mitre_details["mitigations"]:
                                                    with st.expander(f"{mitigation['name']} ({mitigation['id']})", expanded=False):
                                                        st.markdown("### Description")
                                                        st.markdown(mitigation['description'])
                                                        if mitigation.get('reference'):
                                                            st.markdown(f"[MITRE ATT&CK Reference]({mitigation['reference']})")
                                    
                                    if not any([mitre_details["tactics"], mitre_details["techniques"], mitre_details["mitigations"]]):
                                        st.info("No MITRE ATT&CK information available for this case.")
                    else:
                        st.info(f"No cases found for host {selected_host}")
            else:
                st.info("No hosts available for analysis")
        
        # Overall distribution of alerts by host
        col1, col2 = st.columns(2)
        with col1:
        
            st.subheader("Alert Distribution by Host")
            with db.session() as session:
                alerts_by_host_count = TheHiveQueries.get_alert_distribution_by_host(session)
                
                if not alerts_by_host_count.empty:
                    # Add controls for host alert display
                    host_alert_options = ['Top 10', 'Top 20', 'Top 50', 'All']
                    host_alert_selection = st.radio(
                        "Display Count:", 
                        host_alert_options,
                        horizontal=True,
                        key="host_alert_count"
                    )
                    
                    # Apply display limit
                    if host_alert_selection == 'Top 10':
                        display_limit = 10
                    elif host_alert_selection == 'Top 20':
                        display_limit = 20
                    elif host_alert_selection == 'Top 50':
                        display_limit = 50
                    else:  # 'All' option
                        display_limit = len(alerts_by_host_count)
                    
                    # Create filtered dataset
                    display_host_alerts = alerts_by_host_count.head(display_limit)
                    
                    # Create the chart
                    fig = px.bar(
                        display_host_alerts, 
                        x="hostname", 
                        y="alert_count", 
                        color="alert_count",
                        title=f"Hosts by Alert Count ({host_alert_selection})",
                        height=500
                    )
                    
                    if len(display_host_alerts) > 10:
                        fig.update_layout(
                            xaxis_tickangle=-45  # Angle the labels
                        )
                    
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No data available for alert distribution by host")
        with col2:
        # Overall distribution of cases by host
            st.subheader("Case Distribution by Host")
            with db.session() as session:
                cases_by_host_count = TheHiveQueries.get_case_distribution_by_host(session)
                
                if not cases_by_host_count.empty:
                    # Add controls for host case display
                    host_case_options = ['Top 10', 'Top 20', 'Top 50', 'All']
                    host_case_selection = st.radio(
                        "Display Count:", 
                        host_case_options,
                        horizontal=True,
                        key="host_case_count"
                    )
                    
                    # Apply display limit
                    if host_case_selection == 'Top 10':
                        display_limit = 10
                    elif host_case_selection == 'Top 20':
                        display_limit = 20
                    elif host_case_selection == 'Top 50':
                        display_limit = 50
                    else:  # 'All' option
                        display_limit = len(cases_by_host_count)
                    
                    # Create filtered dataset
                    display_host_cases = cases_by_host_count.head(display_limit)
                    
                    # Create the chart
                    fig = px.bar(
                        display_host_cases, 
                        x="hostname", 
                        y="case_count", 
                        color="case_count",
                        title=f"Hosts by Case Count ({host_case_selection})",
                        height=500
                    )
                    
                    if len(display_host_cases) > 10:
                        fig.update_layout(
                            xaxis_tickangle=-45  # Angle the labels
                        )
                    
                    st.plotly_chart(fig, use_container_width=True)
                else:
                    st.info("No data available for case distribution by host")
        
    
    
    
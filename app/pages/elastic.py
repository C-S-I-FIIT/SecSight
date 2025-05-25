import streamlit as st
import pandas as pd
from datetime import datetime, timedelta
import plotly.express as px
from typing import Optional, Dict, List, Any

from app.db.queries.elastic import ElasticQueries
from app.db.database import Database
from app.db.models import Host, NetBoxTag, tag_device_rule_map
from app.charts.bar_chart import create_bar_chart
from app.charts.pie_chart import create_pie_chart
from app.charts.timeline_chart import create_timeline_chart
from app.charts.heatmap_chart import create_heatmap
from app.charts.treemap_chart import create_treemap


def elastic_page():
    st.title("Elasticsearch Log Analysis")
    
    # Sidebar configuration
    with st.sidebar:
        st.header("Elastic Configuration")
        
        # Index selection
        index = st.text_input("Elasticsearch Index", value="logstash-*")
        
        # Date range selection
        st.subheader("Time Range")
        date_option = st.radio(
            "Select time range",
            ["Last 24 hours", "Last 7 days", "Last 30 days", "Custom range"]
        )
        
        # Calculate start and end dates based on selection
        end_date = datetime.now()
        
        if date_option == "Last 24 hours":
            start_date = end_date - timedelta(days=1)
        elif date_option == "Last 7 days":
            start_date = end_date - timedelta(days=7)
        elif date_option == "Last 30 days":
            start_date = end_date - timedelta(days=30)
        else:  # Custom range
            col1, col2 = st.columns(2)
            with col1:
                start_date = st.date_input("Start date", value=end_date - timedelta(days=7))
            with col2:
                end_date_input = st.date_input("End date", value=end_date)
                # Set end date to end of day
                end_date = datetime.combine(end_date_input, datetime.max.time())
            
            # Convert start_date to datetime with time at beginning of day
            start_date = datetime.combine(start_date, datetime.min.time())
        
        # Refresh button
        if st.button("Refresh Data"):
            st.success("Data refreshed!")
    
    # Load Host data from database
    with st.spinner("Loading host data from database..."):
        try:
            db = Database()
            with db.session() as session:
                # Query hosts and their tags in a more efficient way
                hosts = session.query(Host).all()
                
                # Create hosts_metadata list
                hosts_metadata = []
                for host in hosts:
                    # Query tags for this host using the association table
                    tags_query = (
                        session.query(NetBoxTag)
                        .join(
                            tag_device_rule_map,
                            NetBoxTag.id == tag_device_rule_map.c.tag_id
                        )
                        .filter(tag_device_rule_map.c.device_id == host.id)
                        .all()
                    )
                    
                    # Format tags as needed by ElasticQueries
                    tags = [{"name": tag.name} for tag in tags_query]
                    
                    # Create the host metadata entry
                    hosts_metadata.append({
                        "hostname": host.hostname,
                        "ip_address": host.ip_address,
                        "role": host.role,
                        "platform_os": host.platform_os,
                        "tags": tags
                    })
                
                st.sidebar.success(f"Loaded {len(hosts_metadata)} hosts from database")
        except Exception as e:
            st.sidebar.error(f"Error loading host data: {str(e)}")
            hosts_metadata = []
    
    # Host Coverage Analysis
    st.header("Host Coverage Analysis")
    
    # Top hosts and bottom hosts side by side
    col1, col2 = st.columns(2)
    
    # Top 10 devices with most logs
    with col1:
        with st.spinner("Loading top hosts by log volume..."):
            try:
                df_top_hosts = ElasticQueries.get_logs_per_host(
                    index=index, 
                    start_date=start_date,
                    end_date=end_date,
                    top_n=10
                )
                
                if not df_top_hosts.empty:
                    st.subheader("Top 10 Hosts by Log Volume")
                    create_bar_chart(
                        data=df_top_hosts,
                        x_column="host",
                        y_column="log_count",
                        title="Top 10 Hosts by Log Volume",
                        key_prefix="top_hosts"
                    )
                else:
                    st.info("No host data available for the selected time range")
            except Exception as e:
                st.error(f"Error loading top hosts: {str(e)}")
    
    # Top 10 devices with least logs
    with col2:
        with st.spinner("Loading hosts with least logs..."):
            try:
                df_bottom_hosts = ElasticQueries.get_logs_per_host(
                    index=index, 
                    start_date=start_date,
                    end_date=end_date,
                    top_n=10,
                    reverse=True
                )
                
                if not df_bottom_hosts.empty:
                    st.subheader("Hosts with Least Logs")
                    create_bar_chart(
                        data=df_bottom_hosts,
                        x_column="host",
                        y_column="log_count",
                        title="Hosts with Least Logs",
                        key_prefix="bottom_hosts"
                    )
                else:
                    st.info("No host data available for the selected time range")
            except Exception as e:
                st.error(f"Error loading hosts with least logs: {str(e)}")
    
    # # Logs by device role (from database)
    # st.header("Log Volume by Device Role")
    # with st.spinner("Analyzing logs by device role..."):
    #     try:
    #         # Using the updated get_logs_by_device_role method with hosts_metadata
    #         df_role = ElasticQueries.get_logs_by_device_role(
    #             index=index,
    #             hosts_metadata=hosts_metadata,
    #             start_date=start_date,
    #             end_date=end_date
    #         )
            
    #         if not df_role.empty:
    #             col1, col2 = st.columns(2)
    #             with col1:
    #                 create_bar_chart(
    #                     data=df_role,
    #                     x_column="role",
    #                     y_column="log_count",
    #                     title="Log Volume by Device Role",
    #                     key_prefix="role_bar"
    #                 )
    #             with col2:
    #                 create_pie_chart(
    #                     data=df_role,
    #                     names_column="role",
    #                     values_column="log_count",
    #                     title="Distribution of Logs by Device Role",
    #                     key_prefix="role_pie"
    #                 )
    #         else:
    #             st.info("No role data available for the selected time range")
    #     except Exception as e:
    #         st.error(f"Error analyzing logs by device role: {str(e)}")
    
    # # Logs by device tags (from database)
    # st.header("Log Volume by Device Tags")
    # with st.spinner("Analyzing logs by device tags..."):
    #     try:
    #         # Using the updated get_logs_by_device_tags method with hosts_metadata
    #         df_tags = ElasticQueries.get_logs_by_device_tags(
    #             index=index,
    #             hosts_metadata=hosts_metadata,
    #             start_date=start_date,
    #             end_date=end_date
    #         )
            
    #         if not df_tags.empty and len(df_tags) > 1:
    #             col1, col2 = st.columns(2)
    #             with col1:
    #                 create_bar_chart(
    #                     data=df_tags,
    #                     x_column="tag",
    #                     y_column="log_count",
    #                     title="Log Volume by Device Tags",
    #                     key_prefix="tag_bar"
    #                 )
    #             with col2:
    #                 create_treemap(
    #                     data=df_tags,
    #                     path_column="tag",
    #                     values_column="log_count",
    #                     title="Treemap of Logs by Device Tags",
    #                     key_prefix="tag_treemap"
    #                 )
    #         else:
    #             st.info("No tag data available for the selected time range")
    #     except Exception as e:
    #         st.error(f"Error analyzing logs by device tags: {str(e)}")
    
    # Security Analysis
    st.header("Security Analysis")
    
    # Event Provider Analysis
    st.subheader("Logs by Event Provider")
    with st.spinner("Analyzing logs by event provider..."):
        try:
            df_providers = ElasticQueries.get_logs_by_provider(
                index=index,
                start_date=start_date,
                end_date=end_date
            )
            
            if not df_providers.empty:
                col1, col2 = st.columns(2)
                with col1:
                    # Top 10 providers
                    top_providers = df_providers.head(10).copy()
                    create_bar_chart(
                        data=top_providers,
                        x_column="provider",
                        y_column="log_count",
                        title="Top 10 Event Providers",
                        key_prefix="provider_bar"
                    )
                with col2:
                    create_pie_chart(
                        data=top_providers,
                        names_column="provider",
                        values_column="log_count",
                        title="Distribution of Top Event Providers",
                        key_prefix="provider_pie"
                    )
            else:
                st.info("No provider data available for the selected time range")
        except Exception as e:
            st.error(f"Error analyzing logs by event provider: {str(e)}")
    
    # Log Severity Analysis
    st.subheader("Logs by Severity Level")
    with st.spinner("Analyzing logs by severity..."):
        try:
            df_severity = ElasticQueries.get_logs_by_severity(
                index=index,
                start_date=start_date,
                end_date=end_date
            )
            
            if not df_severity.empty:
                col1, col2 = st.columns(2)
                with col1:
                    create_bar_chart(
                        data=df_severity,
                        x_column="severity",
                        y_column="log_count",
                        title="Log Count by Severity",
                        key_prefix="severity_bar"
                    )
                with col2:
                    create_pie_chart(
                        data=df_severity,
                        names_column="severity",
                        values_column="log_count",
                        title="Distribution of Log Severity",
                        key_prefix="severity_pie"
                    )
            else:
                st.info("No severity data available for the selected time range")
        except Exception as e:
            st.error(f"Error analyzing logs by severity: {str(e)}")
    
    # Time-based Analysis
    st.header("Time-based Analysis")
    
    # Timeline of logs
    st.subheader("Log Volume Timeline")
    
    interval = st.selectbox(
        "Select time interval",
        ["hour", "day", "week", "month"],
        index=1
    )
    
    with st.spinner("Generating log timeline..."):
        try:
            df_timeline = ElasticQueries.get_logs_timeline(
                index=index,
                start_date=start_date,
                end_date=end_date,
                interval=interval
            )
            
            if not df_timeline.empty:
                create_timeline_chart(
                    data=df_timeline,
                    x_column="timestamp",
                    y_column="log_count",
                    title=f"Log Volume Over Time (by {interval})",
                    key_prefix="timeline"
                )
            else:
                st.info("No timeline data available for the selected time range")
        except Exception as e:
            st.error(f"Error generating log timeline: {str(e)}")


if __name__ == "__main__":
    elastic_page()

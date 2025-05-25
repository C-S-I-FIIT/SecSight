import streamlit as st
import plotly.express as px
import plotly.graph_objects as go
import pandas as pd
from app.db.queries import get_rule_coverage_by_host, get_rule_coverage_stats, get_rule_coverage_by_tactic, get_host_coverage_timeline

def plot_rule_coverage_by_host():
    """Plot rule coverage by host as a bar chart"""
    data = get_rule_coverage_by_host()
    df = pd.DataFrame(data, columns=['hostname', 'total_rules', 'covered_rules'])
    df['coverage_percentage'] = (df['covered_rules'] / df['total_rules'] * 100).round(2)
    
    fig = px.bar(df, 
                 x='hostname', 
                 y='coverage_percentage',
                 title='Rule Coverage by Host',
                 labels={'coverage_percentage': 'Coverage (%)', 'hostname': 'Host'},
                 color='coverage_percentage',
                 color_continuous_scale='RdYlGn')
    
    fig.update_layout(
        xaxis_tickangle=-45,
        yaxis_range=[0, 100]
    )
    st.plotly_chart(fig, use_container_width=True)

def plot_rule_coverage_stats():
    """Plot overall rule coverage statistics"""
    stats = get_rule_coverage_stats()
    if stats:
        total_rules, covered_rules = stats
        coverage_percentage = (covered_rules / total_rules * 100) if total_rules > 0 else 0
        
        col1, col2, col3, col4 = st.columns(4)
        with col1:
            st.metric("Total Rules", total_rules)
        with col2:
            st.metric("Covered Rules", covered_rules)
        with col3:
            st.metric("Coverage %", f"{coverage_percentage:.2f}%")
        with col4:
            st.metric("Uncovered Rules", total_rules - covered_rules)

def plot_rule_coverage_by_tactic():
    """Plot rule coverage by MITRE tactic as a radar chart"""
    data = get_rule_coverage_by_tactic()
    df = pd.DataFrame(data, columns=['tactic_name', 'total_rules', 'covered_rules'])
    df['coverage_percentage'] = (df['covered_rules'] / df['total_rules'] * 100).round(2)
    
    fig = go.Figure()
    
    fig.add_trace(go.Scatterpolar(
        r=df['coverage_percentage'],
        theta=df['tactic_name'],
        fill='toself',
        name='Coverage %'
    ))
    
    fig.update_layout(
        polar=dict(
            radialaxis=dict(
                visible=True,
                range=[0, 100]
            )
        ),
        title='Rule Coverage by MITRE Tactic',
        showlegend=False
    )
    
    st.plotly_chart(fig, use_container_width=True)

def plot_host_coverage_timeline(host_id):
    """Plot coverage timeline for a specific host"""
    data = get_host_coverage_timeline(host_id)
    if data:
        df = pd.DataFrame(data, columns=['created_at', 'total_rules', 'covered_rules'])
        df['coverage_percentage'] = (df['covered_rules'] / df['total_rules'] * 100).round(2)
        
        fig = px.line(df, 
                     x='created_at', 
                     y='coverage_percentage',
                     title='Host Coverage Timeline',
                     labels={'coverage_percentage': 'Coverage (%)', 'created_at': 'Date'},
                     markers=True)
        
        fig.update_layout(
            yaxis_range=[0, 100],
            xaxis_title='Date',
            yaxis_title='Coverage (%)'
        )
        
        st.plotly_chart(fig, use_container_width=True) 
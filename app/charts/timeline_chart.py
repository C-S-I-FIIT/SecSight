import streamlit as st
import plotly.express as px
import pandas as pd

def create_timeline_chart(data, x_column, y_column, color_column=None, title="Timeline Chart", 
                         x_title=None, y_title=None, color_map=None, markers=True, key_prefix="timeline"):
    """
    Create a reusable timeline chart component
    
    Args:
        data: DataFrame or list of dictionaries
        x_column: Column name for x-axis (time)
        y_column: Column name for y-axis
        color_column: Column name for color (optional)
        title: Chart title
        x_title: X-axis title (defaults to x_column if None)
        y_title: Y-axis title (defaults to y_column if None)
        color_map: Dictionary mapping values to colors
        markers: Whether to show markers on the line
        key_prefix: Prefix for the chart key to ensure uniqueness
    """
    # Convert to DataFrame if needed
    if not isinstance(data, pd.DataFrame):
        df = pd.DataFrame(data)
    else:
        df = data
    
    # Check if required columns exist
    if x_column not in df.columns or y_column not in df.columns:
        st.warning(f"Required columns missing: {x_column} or {y_column}")
        return
    
    # Create line chart
    fig = px.line(
        df,
        x=x_column,
        y=y_column,
        color=color_column,
        color_discrete_map=color_map,
        title=title,
        markers=markers
    )
    
    # Update layout
    fig.update_layout(
        xaxis_title=x_title if x_title else x_column,
        yaxis_title=y_title if y_title else y_column,
        height=400,
        xaxis=dict(
            type='date',
            tickformat='%Y-%m-%d %H:%M:%S'
        )
    )
    
    # Display chart
    st.plotly_chart(fig, use_container_width=True, key=f"{key_prefix}_{x_column}_{y_column}")
    
    return fig 
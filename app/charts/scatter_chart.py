import streamlit as st
import plotly.express as px
import pandas as pd

def create_scatter_chart(data, x_column, y_column, color_column=None, size_column=None,
                        hover_name=None, hover_data=None, title="Scatter Chart", 
                        x_title=None, y_title=None, color_map=None, key_prefix="scatter"):
    """
    Create a reusable scatter chart component
    
    Args:
        data: DataFrame or list of dictionaries
        x_column: Column name for x-axis
        y_column: Column name for y-axis
        color_column: Column name for color (optional)
        size_column: Column name for point size (optional)
        hover_name: Column name for hover title
        hover_data: List of column names to show on hover
        title: Chart title
        x_title: X-axis title (defaults to x_column if None)
        y_title: Y-axis title (defaults to y_column if None)
        color_map: Dictionary mapping values to colors
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
    
    # Validate hover_data columns exist
    if hover_data:
        hover_data = [col for col in hover_data if col in df.columns]
    
    # Create scatter chart
    fig = px.scatter(
        df,
        x=x_column,
        y=y_column,
        color=color_column,
        size=size_column,
        hover_name=hover_name if hover_name in df.columns else None,
        hover_data=hover_data,
        color_discrete_map=color_map,
        title=title
    )
    
    # Update layout
    fig.update_layout(
        xaxis_title=x_title if x_title else x_column,
        yaxis_title=y_title if y_title else y_column,
        height=400
    )
    
    # Display chart
    st.plotly_chart(fig, use_container_width=True, key=f"{key_prefix}_{x_column}_{y_column}")
    
    return fig 
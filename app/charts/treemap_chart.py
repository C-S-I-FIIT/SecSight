import streamlit as st
import plotly.express as px
import pandas as pd

def create_treemap(data, path, values, color=None, title="Treemap", 
                  color_continuous_scale=None, hover_data=None, key_prefix="treemap"):
    """
    Create a reusable treemap component
    
    Args:
        data: DataFrame or list of dictionaries
        path: List of column names that define the hierarchy levels
        values: Column name for size values
        color: Column name for color (optional)
        title: Chart title
        color_continuous_scale: Color scale for continuous values
        hover_data: List of column names to show on hover
        key_prefix: Prefix for the chart key to ensure uniqueness
    """
    # Convert to DataFrame if needed
    if not isinstance(data, pd.DataFrame):
        df = pd.DataFrame(data)
    else:
        df = data
    
    # Check if required columns exist
    if not all(col in df.columns for col in path) or values not in df.columns:
        st.warning(f"Required columns missing for treemap")
        return
    
    # Validate hover_data columns exist
    if hover_data:
        hover_data = [col for col in hover_data if col in df.columns]
    
    # Create treemap
    fig = px.treemap(
        df,
        path=path,
        values=values,
        color=color,
        title=title,
        hover_data=hover_data,
        color_continuous_scale=color_continuous_scale
    )
    
    # Update layout
    fig.update_layout(
        height=600,
        margin=dict(t=50, l=25, r=25, b=25)
    )
    
    # Display chart
    st.plotly_chart(fig, use_container_width=True, key=f"{key_prefix}_{'_'.join(path)}")
    
    return fig 
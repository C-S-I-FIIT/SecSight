import streamlit as st
import plotly.express as px
import pandas as pd

def create_heatmap(data, x_column, y_column, z_column, title="Heatmap", 
                  x_title=None, y_title=None, color_scale=None, key_prefix="heatmap"):
    """
    Create a reusable heatmap component
    
    Args:
        data: DataFrame or list of dictionaries
        x_column: Column name for x-axis
        y_column: Column name for y-axis
        z_column: Column name for z-axis (values)
        title: Chart title
        x_title: X-axis title (defaults to x_column if None)
        y_title: Y-axis title (defaults to y_column if None)
        color_scale: Color scale for heatmap
        key_prefix: Prefix for the chart key to ensure uniqueness
    """
    # Convert to DataFrame if needed
    if not isinstance(data, pd.DataFrame):
        df = pd.DataFrame(data)
    else:
        df = data
    
    # Check if required columns exist
    if x_column not in df.columns or y_column not in df.columns or z_column not in df.columns:
        st.warning(f"Required columns missing: {x_column}, {y_column}, or {z_column}")
        return
    
    # Create pivot table for heatmap
    pivot_df = df.pivot_table(index=y_column, columns=x_column, values=z_column, aggfunc='mean')
    
    # Create heatmap
    fig = px.imshow(
        pivot_df,
        color_continuous_scale=color_scale if color_scale else 'RdBu_r',
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
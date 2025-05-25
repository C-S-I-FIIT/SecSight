import streamlit as st
import plotly.express as px
import pandas as pd

def create_pie_chart(data, names_column, values_column, title="Pie Chart", 
                    color_map=None, key_prefix="pie"):
    """
    Create a reusable pie chart component
    
    Args:
        data: DataFrame or list of dictionaries
        names_column: Column name for pie slice names
        values_column: Column name for pie slice values
        title: Chart title
        color_map: Dictionary mapping values to colors
        key_prefix: Prefix for the chart key to ensure uniqueness
    """
    # Convert to DataFrame if needed
    if not isinstance(data, pd.DataFrame):
        df = pd.DataFrame(data)
    else:
        df = data
    
    # Check if required columns exist
    if names_column not in df.columns or values_column not in df.columns:
        st.warning(f"Required columns missing: {names_column} or {values_column}")
        return
    
    # Create pie chart
    fig = px.pie(
        df,
        names=names_column,
        values=values_column,
        color=names_column,
        color_discrete_map=color_map,
        title=title
    )
    
    # Update layout
    fig.update_layout(
        height=400
    )
    
    # Display chart
    st.plotly_chart(fig, use_container_width=True, key=f"{key_prefix}_{names_column}_{values_column}")
    
    return fig 
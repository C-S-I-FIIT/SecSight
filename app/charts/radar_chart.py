import streamlit as st
import plotly.graph_objects as go
import pandas as pd

def create_radar_chart(data, category_column, value_columns, labels=None, title="Radar Chart",
                      color_sequence=None, fill=True, key_prefix="radar"):
    """
    Create a reusable radar chart component
    
    Args:
        data: DataFrame or list of dictionaries
        category_column: Column name for categories around the radar
        value_columns: List of column names for radar chart values
        labels: Dictionary mapping column names to display labels
        title: Chart title
        color_sequence: List of colors for the radar traces
        fill: Whether to fill the radar chart areas
        key_prefix: Prefix for the chart key to ensure uniqueness
    """
    # Convert to DataFrame if needed
    if not isinstance(data, pd.DataFrame):
        df = pd.DataFrame(data)
    else:
        df = data
    
    # Check if required columns exist
    if category_column not in df.columns or not all(col in df.columns for col in value_columns):
        st.warning(f"Required columns missing for radar chart")
        return
    
    # If labels not provided, use column names
    if labels is None:
        labels = {col: col for col in value_columns}
    
    # Create figure
    fig = go.Figure()
    
    # Get unique categories
    categories = df[category_column].unique()
    
    # Add a trace for each value column
    for i, value_col in enumerate(value_columns):
        fig.add_trace(go.Scatterpolar(
            r=df[value_col],
            theta=df[category_column],
            name=labels.get(value_col, value_col),
            fill='toself' if fill else None,
            line=dict(width=2)
        ))
    
    # Update layout
    fig.update_layout(
        title=title,
        polar=dict(
            radialaxis=dict(
                visible=True,
            ),
        ),
        showlegend=True,
        height=500,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        )
    )
    
    # Display chart
    st.plotly_chart(fig, use_container_width=True, key=f"{key_prefix}_{category_column}_{'_'.join(value_columns)}")
    
    return fig

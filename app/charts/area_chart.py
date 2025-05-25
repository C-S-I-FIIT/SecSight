import streamlit as st
import plotly.graph_objects as go
import pandas as pd

def create_area_chart(data, x_column, y_columns, labels=None, title="Area Chart",
                     x_title=None, y_title=None, fill='tozeroy', key_prefix="area"):
    """
    Create a reusable area chart component
    
    Args:
        data: DataFrame or list of dictionaries
        x_column: Column name for x-axis
        y_columns: List of column names for y-axis values
        labels: Dictionary mapping column names to display labels
        title: Chart title
        x_title: X-axis title (defaults to x_column if None)
        y_title: Y-axis title
        fill: Fill type ('tozeroy', 'tonexty', etc.)
        key_prefix: Prefix for the chart key to ensure uniqueness
    """
    # Convert to DataFrame if needed
    if not isinstance(data, pd.DataFrame):
        df = pd.DataFrame(data)
    else:
        df = data
    
    # Check if required columns exist
    if x_column not in df.columns or not all(col in df.columns for col in y_columns):
        st.warning(f"Required columns missing for area chart")
        return
    
    # Create figure
    fig = go.Figure()
    
    # If labels not provided, use column names
    if labels is None:
        labels = {col: col for col in y_columns}
    
    # Add traces for each y column
    for i, y_col in enumerate(y_columns):
        fig.add_trace(
            go.Scatter(
                x=df[x_column],
                y=df[y_col],
                name=labels.get(y_col, y_col),
                fill=fill,
                mode='lines',
                line=dict(width=1.5),
            )
        )
    
    # Update layout
    fig.update_layout(
        title=title,
        xaxis_title=x_title if x_title else x_column,
        yaxis_title=y_title,
        height=400,
        legend=dict(
            orientation="h",
            yanchor="bottom",
            y=1.02,
            xanchor="right",
            x=1
        )
    )
    
    # Display chart
    st.plotly_chart(fig, use_container_width=True, key=f"{key_prefix}_{x_column}_{'_'.join(y_columns)}")
    
    return fig 
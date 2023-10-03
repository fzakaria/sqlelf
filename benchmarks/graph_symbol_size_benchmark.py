#! /usr/bin/env python3

from plotnine import *
import pandas as pd
import numpy as np

# Raw data
data = {
    "Number of Functions": [10, 100, 1000, 10000, 100000],
    "readelf": [
        0.0052862250013276935,
        0.005087099008960649,
        0.005879847012693062,
        0.01378464701701887,
        0.09143825399223715,
    ],
    "sqlelf": [
        0.026774031983222812,
        0.07022259500809014,
        0.5325515430013184,
        5.426244292000774,
        51.41806371998973,
    ],
    "sqlelf-memoized": [
        0.0006310690077953041,
        0.0012372269993647933,
        0.0005934310029260814,
        0.0008586860203649849,
        0.0030715609900653362,
    ],
}

# Create the pandas DataFrame
df = pd.DataFrame(data=data)

# Melt the data
df_melted = pd.melt(
    df,
    id_vars=["Number of Functions"],
    value_vars=["readelf", "sqlelf", "sqlelf-memoized"],
    var_name="Category",
    value_name="Value",
)

plot = (
    ggplot(
        df_melted, aes(x="Number of Functions", y="Value", color="Category")
    )  # Define data and aesthetics
    + geom_line()  # Add line geometry
    + theme_classic()  # Minimal theme
    + labs(title="", x="Number of Functions", y="Time (s)", color="")
    + scale_x_continuous(trans="log10")
    + scale_y_log10(expand=(0, 0, 0, 1))
)

save_as_pdf_pages([plot])

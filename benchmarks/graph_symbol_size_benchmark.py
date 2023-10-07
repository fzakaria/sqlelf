#! /usr/bin/env python3

import pandas as pd
from plotnine import (
    aes,
    geom_line,
    ggplot,
    labs,
    save_as_pdf_pages,
    scale_x_continuous,
    scale_y_log10,
    theme_classic,
)

# Raw data
data = {
    "Number of Functions": [10, 100, 1000, 10000, 100000],
    "readelf": [
        0.004524321004282683,
        0.004533555009402335,
        0.005225651984801516,
        0.012913715007016435,
        0.08858381301979534,
    ],
    "sqlelf": [
        0.02732730400748551,
        0.0717524380015675,
        0.5335653759830166,
        5.1397658770147245,
        51.25160684299772,
    ],
    "sqlelf-memoized": [
        0.000236856983974576,
        0.00015781400725245476,
        0.0001789960078895092,
        0.0003311840118840337,
        0.002041122002992779,
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
    + labs(title="", x="Number of Symbols", y="Time (s)", color="")
    + scale_x_continuous(trans="log10")
    + scale_y_log10(expand=(0, 0, 0, 1))
)

save_as_pdf_pages([plot])

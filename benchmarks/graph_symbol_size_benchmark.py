#! /usr/bin/env python3

from plotnine import *
import pandas as pd
import numpy as np

# Raw data
data = {
    "Number of Functions": [10**exponent for exponent in range(1, 6)],
    "readelf": [
        0.005350531006115489,
        0.005340991003322415,
        0.005842811006004922,
        0.01410250501066912,
        0.09029568900587037,
    ],
    "sqlelf": [
        0.02874817499832716,
        0.07305189099861309,
        0.53968190800515,
        5.312782863009488,
        51.02671549099614,
    ],
}

# Create the pandas DataFrame
df = pd.DataFrame(data=data)

# Melt the data
df_melted = pd.melt(
    df,
    id_vars=["Number of Functions"],
    value_vars=["readelf", "sqlelf"],
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

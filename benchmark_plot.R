# https://stackoverflow.com/questions/13035295/overlay-bar-graphs-in-ggplot2
# https://stackoverflow.com/questions/10941225/horizontal-barplot-in-ggplot2

library(ggplot2)
library(reshape)
library(svglite)

args <- commandArgs(trailingOnly = TRUE)

pi4 <- read.csv(
  "benchmark-results/2024-10-18T16-06-12+00-00_bench-oqs_Raspberry-Pi-4.csv",
  TRUE, "\t",
  check.names = FALSE
)
pi3 <- read.csv(
  "benchmark-results/2024-11-08T06-51-26+00-00_bench-oqs_Raspberry-Pi-3-Model-B-1GB.csv",
  TRUE, "\t",
  check.names = FALSE
)
nuc <- read.csv(
  "benchmark-results/2024-11-08T10-11-07+00-00_bench-oqs_Intel-NUC-BXNUC10i5FNK2-8GB.csv",
  TRUE, "\t",
  check.names = FALSE
)
laptop <- read.csv(
  "benchmark-results/2024-10-18T14-11-54+00-00_bench-oqs_Laptop-HP-EliteBook-840-G10.csv",
  TRUE, "\t",
  check.names = FALSE
)

y_scale <- NULL
plot_img_name <- NULL
plot_title <- NULL
row_start_idx <- NULL
number_algorithms <- 47
plot_height <- NULL

if (length(args) > 0) {
  if (args[1] == "sign") {
    y_scale <<- c(
      0.000, 0.01, 0.02, 0.03, 0.04, 0.05
    )
    plot_img_name <- "plots/sign.svg"
    #plot_img_name <- "plots/sign.jpg"
    plot_title <- "Signing Time"
    row_start_idx <- 48
    plot_height <- 6
  } else if (args[1] == "verify") {
    y_scale <<- c(0.000, 0.005, 0.010, 0.015, 0.020, 0.025, 0.030)
    plot_img_name <- "plots/verify.svg"
    #plot_img_name <- "plots/verify.jpg"
    plot_title <- "Verification Time"
    row_start_idx <- 95
    plot_height <- 7
  } else if (args[1] == "sphincs_sign") {
    y_scale <<- c(0, 2, 4, 6, 8, 10, 12, 14, 16)
    plot_img_name <- "plots/sphincs_sign.svg"
    #plot_img_name <- "plots/sphincs_sign.jpg"
    plot_title <- "SPHINCS Signing Time"
    row_start_idx <- 61
    number_algorithms <- 12
    plot_height <- 3
  } else {
    stop("Unknown argument found, please select one of the following benchmark types:\nsign | verify | sphincs_sign")
  }

  # Key Generation: 1, Signing: 48, Verification: 95
  number_rows <- row_start_idx + number_algorithms - 1
  # SPHINCS start index excluded
  sphincs_ex_start_idx <- row_start_idx + 13 - 1
  # SPHINCS end index excluded (end_idx + number_sphincs_algorithms + include_start_idx + exclude_end_idx)
  sphincs_ex_end_idx <- sphincs_ex_start_idx + 11 + 1 + 1

  # Data
  pi4_values <- NULL
  pi3_values <- NULL
  nuc_values <- NULL
  laptop_values <- NULL

  # Algorithms x-axis
  x <- NULL

  if(args[1] == "sign") {
    pi4_values <- data.frame(values = pi4$"cpu-time-average_seconds"[c(row_start_idx:sphincs_ex_start_idx, sphincs_ex_end_idx:number_rows)])
    pi3_values <- data.frame(values = pi3$"cpu-time-average_seconds"[c(row_start_idx:sphincs_ex_start_idx, sphincs_ex_end_idx:number_rows)])
    nuc_values <- data.frame(values = nuc$"cpu-time-average_seconds"[c(row_start_idx:sphincs_ex_start_idx, sphincs_ex_end_idx:number_rows)])
    laptop_values <- data.frame(values = laptop$"cpu-time-average_seconds"[c(row_start_idx:sphincs_ex_start_idx, sphincs_ex_end_idx:number_rows)])

    x <- as.character(pi4$"algorithm"[c(row_start_idx:sphincs_ex_start_idx, sphincs_ex_end_idx:number_rows)])
  } else {
    pi4_values <- data.frame(values = pi4$"cpu-time-average_seconds"[row_start_idx:number_rows])
    pi3_values <- data.frame(values = pi3$"cpu-time-average_seconds"[row_start_idx:number_rows])
    nuc_values <- data.frame(values = nuc$"cpu-time-average_seconds"[row_start_idx:number_rows])
    laptop_values <- data.frame(values = laptop$"cpu-time-average_seconds"[row_start_idx:number_rows])

    x <- as.character(pi4$algorithm[row_start_idx:number_rows])
  }

  to_plot <- data.frame(x = x, y1 = pi3_values, y2 = pi4_values, y3 = nuc_values, y4 = laptop_values)
  melted <- melt(to_plot, id = "x")

  p <- ggplot(melted, aes(x = x, y = value, fill = variable)) +
    geom_bar(stat = "identity", position = "identity", alpha = 1, width = 0.3) +
    coord_flip() +
    scale_fill_manual(
      values =
        c(
          "values" = "darkgreen", "values.1" = "red",
          "values.2" = "orange", "values.3" = "blue"
        ),
      labels = c(
        "values" = "Pi3", "values.1" = "Pi4",
        "values.2" = "NUC", "values.3" = "Laptop"
      )
    ) +
    labs(
      fill = "Device", x = "Algorithms", y = "Average Time (seconds)",
      title = plot_title
    ) +
    scale_y_continuous(expand = c(0, 0), breaks = y_scale, limits = c(0, y_scale[length(y_scale)])) +
    theme_classic()

  ggsave(plot_img_name, plot = p, width = 6, height = plot_height, create = TRUE)
} else {
  print("Please define benchmark type as argument (sign | verify | sphincs_sign)")
}

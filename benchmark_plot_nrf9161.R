# https://stackoverflow.com/questions/13035295/overlay-bar-graphs-in-ggplot2
# https://stackoverflow.com/questions/10941225/horizontal-barplot-in-ggplot2

library(ggplot2)
library(reshape)
library(svglite)

nrf9161 <- read.csv(
  "benchmark-results/2024-12-03T14-00-05+00-00_bench-oqs_Nordic-nRF9161dk.csv",
  TRUE, ",", check.names = FALSE
)

# Data
algorithms <- nrf9161[seq(1, min(nrow(nrf9161), 140), by = 3), "algorithm"]
nrf9161_keygen_values <- nrf9161[seq(1, min(nrow(nrf9161), 140), by = 3), "cpu-time-average_seconds", drop = FALSE]
nrf9161_sign_values <- nrf9161[seq(2, min(nrow(nrf9161), 141), by = 3), "cpu-time-average_seconds", drop = FALSE]
nrf9161_verify_values <- nrf9161[seq(3, min(nrow(nrf9161), 142), by = 3), "cpu-time-average_seconds", drop = FALSE]

# Algorithms y-axis
x <- as.character(algorithms)

to_plot <- data.frame(x = x, y1 = nrf9161_keygen_values, y2 = nrf9161_sign_values, y3 = nrf9161_verify_values)
melted <- melt(to_plot, id = "x")

print(ggplot(melted, aes(x = x, y = value, fill = variable)) +
    geom_bar(stat = "identity", position = "stack", alpha = 1, width = 0.3) +
    coord_flip() +
    scale_fill_manual(values =
                        c("cpu.time.average_seconds" = "darkgreen", "cpu.time.average_seconds.1" = "red", "cpu.time.average_seconds.2" = "orange"),
                      labels = c("cpu.time.average_seconds" = "Key Generation", "cpu.time.average_seconds.1" = "Signing", "cpu.time.average_seconds.2" = "Verification")) +
    labs(fill = "Operation", x = "Algorithms", y = "Average Time (seconds)",
         title = "Nordic nRF9161dk") +
    scale_y_log10() +
    theme_classic()
)

ggsave("plots/nrf9161.svg", width = 6, height = 7, create = TRUE)
#ggsave("plots/nrf9161.jpg", width = 6, height = 7, create = TRUE)


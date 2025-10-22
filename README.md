# Proof-of-Concept: Towards Stateless Post-Quantum Remote Attestation for IoT Using TPM and DICE

**WARNING:** *THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.*

For further details, see the [LICENSE](LICENSE) file.

## Overview

This repository contains the:
* Proof-of-concept (PoC) implementation with [sample console output](sample-output.txt) in folder [poc](./poc/)
* Benchmark results in folder [benchmark-results](./benchmark-results/)
* Plots in folder [plots](./plots/)
* R scripts to generate plots as `benchmark_plot.R` and `benchmark_plot_nrf9161.R`
* Formal analysis using Verifpal in folder [formal-proof](./formal-proof/)

Everything was tested under a Ubuntu 24.04 64-bit (amd64) operating system.

## Run the PoC

1. Install *gcc* and the *Mbed TLS* library (see `Dockerfile` in [poc](./poc/) folder)
2. Change to folder [poc](./poc/)
3. Run `make`
4. Run `./stateless_ra_demo`

## Run the PoC in a Container

1. [Install Docker](https://docs.docker.com/engine/install/)
2. Change to folder [poc](./poc/)
3. Build container: `docker build -t 'me/stateless-ra-poc:1.5.3' .`
4. Run container `docker run --rm -it --init 'me/stateless-ra-poc:1.5.3'`
5. In the container, run: `make clean && make && ./stateless_ra_demo`
6. Exit the container: `exit`

For the geeks, here a one-liner (assuming your working directory is the `poc` folder):

```
docker build -t 'me/stateless-ra-poc:1.5.3' . && docker run --rm -it --init 'me/stateless-ra-poc:1.5.3' sh -c 'cd ~/poc/ && make clean && make && ./stateless_ra_demo && make clean; exit'
```

## Generate the Plots

1. Install R: `sudo apt install r-base`

2. Install R packages: `Rscript -e 'install.packages(c("ggplot2","reshape","svglite"))'`

3. Run Nordic nRF9161 benchmark scripts:

   ```
   Rscript benchmark_plot_nrf9161.R
   ```

4. Run other benchmark scripts:

   ```
   for op in 'sign' 'verify' 'sphincs_sign'; do Rscript benchmark_plot.R "${op}"; done
   ```

## Run the Formal Analysis (Verifpal)

1. Install Verifpal following the instructions on their website: <https://verifpal.com/>

2. Run the analysis with: `verifpal verify formal-proof/stateless-ra.vp`


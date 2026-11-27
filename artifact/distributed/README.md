# Two-site verification experiment

This experiment places an O-TBC producer, scheduler, and SQLite-backed closure service on one Linux host. Odd-numbered registered worker identities and a separate full-transcript consumer run on a second host in the split placement. All workers run on the producer host in the local placement. The same second-host consumer verifies completed decisions in both placements. Input signing precedes the timed path. Task batches and all signing keys are generated for the experiment.

The snapshots derive from O-TBC artifact commit `000b0e4`. Changes select an explicit libcrypto for ML-DSA, serialize its native key directly, and expose the existing T2 scheduler through the common trial implementation. Each campaign's environment record gives the SHA-256 digest of every executed source file.

The protocols run the same worker, authenticated-report and closure code. They use the same task and fault seeds within a block. The mobile injection procedure responds to each policy's own cohorts, so its exposed sets can differ by policy. T2 uses the existing two-epoch cohort construction. The driver varies execution order by randomized block. It records started and timely jobs, admitted identities, full outcome counts, producer latency, remote consumer latency, and bytes in application frames. The byte count excludes TCP, TLS, and link-layer overhead. Certified latency statistics exclude unresolved attempts. Sequential goodput includes their times.

The split placement uses authenticated TCP between the two research hosts. Each remote job opens a mutually authenticated TLS connection, then the remote gateway dispatches to the assigned worker over loopback. Worker services bind to loopback on both hosts. The gateway accepts only the producer's configured IP and pinned client certificate. The observer verifies the same signed evidence format as the local verifier. The two systems share a protocol implementation, so their agreement is an end-to-end integration check.

The experiment exercises physical placement and inter-site latency. Each site's identities share its hardware and process environment. Injected report labels obey the specified exposure bounds per attempt. The run measures a sequential producer and records each observed cohort. The separate integrated gate benchmark uses signed admission tickets and independent quota enforcement on one host. A comparison between placements includes the remote gateway, TLS connection setup, and the different worker processors. This campaign uses natural route conditions without artificial delay or enforced report deadlines. CPU columns cover worker payload verification and the remote consumer's signed-transcript checks.

## Run

1. Copy `distributed_trial.py` and the five Python files under `snapshot/` to an isolated directory on each host. Use Python 3.10 or later. Build and verify the matching OpenSSL 3.5.9 shared library on each host with `build_libcrypto.sh`. The EVP wrapper selects the explicit library from `OTBC_LIBCRYPTO`.
2. Generate fresh short-lived endpoint certificates on the two hosts with different key pairs. Give the server certificate the `serverAuth` extended usage and a subject alternative name matching the controller's `--peer-name`. Give the controller certificate `clientAuth` extended usage. Exchange the public certificate files under `peer.pem`. Private keys stay on their generating hosts.
3. Start the remote gateway with an existing network route and a port reachable from the controller. Restrict access with `--peer-ip` to the actual controller source address.

       export OTBC_LIBCRYPTO="$PWD/openssl-3.5.9/libcrypto.so.3"
       python3.10 distributed_trial.py gateway --listen "$REMOTE_ADDRESS" --port 0 \
         --peer-ip "$CONTROLLER_IP" --cert endpoint.pem --key endpoint.key --trust peer.pem

4. Use the allocated port printed by the gateway and run the controller from its own directory.

       export OTBC_LIBCRYPTO="$PWD/openssl-3.5.9/libcrypto.so.3"
       python3.10 distributed_trial.py run --host "$REMOTE_ADDRESS" --port "$PORT" \
         --peer-name "$SERVER_DNS_NAME" --ping-host "$REMOTE_ADDRESS" \
         --cert endpoint.pem --key endpoint.key --trust peer.pem --output results \
         --populations 14 42 --batch 32 --slots 4 --repeats 10 \
         --policies Direct L4 O-TBC T2 --scenarios honest mobile --placements local split

5. Run `python verify_records.py results` and `python summarize.py results`. The first command checks the recorded outcome, accounting, fault mobility and admission counts. The second writes per-cell and block-level summaries, sequential goodput, and paired O-TBC goodput ratios. The paired analysis treats each randomized block as an observation and uses a percentile block bootstrap for cells with at least eight pairs. A figure can be generated with `python plot_multihost.py results/summary.csv --output network_latency.pdf`.

The result bundle contains environment and latency probes plus one attempt, epoch, and job CSV for each population and placement. A round-trip application probe includes the TLS handshake. Use `python measure_tcp.py "$REMOTE_ADDRESS" "$PORT"` on the benchmark Linux controller to record the initial RTT estimate from TCP_INFO. The environment records the interface's nominal speed. Clock synchronization is unnecessary because every attempt, cutoff and producer timing uses the controller's monotonic clock. Worker CPU times and remote verifier CPU times are local durations. Workers at a site share its hardware failure domain.

## Recorded configurations

| Records | Population | Signatures | Policies | Scenarios | Placements | Blocks per cell |
| --- | ---: | ---: | --- | --- | --- | ---: |
| `smoke` | 14 | 8 | DM, L4, O-TBC, T2 | Mobile | Split | 1 |
| `campaign14` | 14 | 32 | DM, L4, O-TBC, T2, ES-QM, ES-S | Honest, mobile | Local, split | 10 |
| `campaign42` | 42 | 32 | DM, L4, O-TBC, T2 | Honest, mobile | Local, split | 10 |

All configurations use four RPC lanes and one valid and one invalid attempt per block and policy. The driver spells DM as `Direct` and ES-S as `ES-stream`. Generate the compact four-policy figure with `python plot_compact_n14.py campaign14/blocks.csv tpds_multihost_n14.pdf`.

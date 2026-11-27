# O-TBC research artifact

This repository contains the scheduler, the temporal feasibility and terminal-cohort oracles, and the experiment drivers for O-TBC. The worker and ledger experiments construct their own payloads and keys and use local processes and loopback sockets. Each driver writes its results locally.

## Environment

Use Python 3.10 or newer and a Linux environment for the systems benchmarks. The CPU measurements read Linux process and cgroup counters. The arithmetic audits use the Python standard library.

    python3 -m venv .venv
    . .venv/bin/activate
    python -m pip install -r requirements.txt
    mkdir -p outputs

The worker and application benchmarks exercised OpenSSL 3.5.9 for ML-DSA. Make its shared crypto library available to the dynamic loader. The CometBFT runners also require the stock CometBFT 0.38.26 executable.

    export LD_LIBRARY_PATH=/path/to/openssl/lib64
    export CRYPTOGRAPHY_OPENSSL_NO_LEGACY=1
    python -c 'import ctypes as c; lib = c.CDLL("libcrypto.so.3"); lib.OpenSSL_version.restype = c.c_char_p; print(lib.OpenSSL_version(0).decode())'
    COMET=/path/to/cometbft

## Arithmetic audits

    python scientific_audit/audit_two_epochs.py
    python scientific_audit/test_terminal_oracle.py
    python scientific_audit/audit_temporal.py --output outputs/temporal_checks.json
    python scientific_audit/audit_horizon.py --output outputs/horizon_checks.json
    python scientific_audit/plot_exact_frontiers.py --output-dir outputs/figures

The depth-two audit writes the exact-cap reference cases consumed by the signed boundary benchmark and the frontier plot. The terminal-oracle check compares weighted choices with concrete finite enumeration. The horizon audit accepts `--full` and `--work` for the larger minimax cases.

## Local worker and closure experiments

    python review_runs/mobility_source/benchmark_mobility.py --output outputs/mobility --repeats 4 --attempts 8
    python review_runs/admission_source/benchmark_admission.py --output outputs/admission --repeats 3 --attempts 8
    python artifact/systems_v8/benchmark.py --output outputs/systems
    python artifact/systems_v8/benchmark_long.py --output outputs/systems-long
    python artifact/systems_v8/benchmark_static.py --output outputs/systems-static
    python artifact/optimistic/benchmark_v6.py --output outputs/deadlines --populations 42 --batches 8 --slots 4 8 --deadlines 25 30 40 50 65 80 100 --guard 100 --repeats 6 --scenarios mobile --truths 0 1 --policies Direct ES-QM ES-stream QT L4 O-TBC
    python artifact/deadlines/closure_ablation.py --output outputs/closure
    python scientific_audit/boundary_benchmark.py --output outputs/boundary
    python scientific_audit/consumer_fanout.py --output outputs/fanout

The mobility and admission drivers carry the worker snapshots used in their respective runs. The deadline procedure measures whether the designated policies certify within the configured reporting window. The signed boundary replay checks the two-epoch reference cases. The consumer fan-out driver measures direct verification and certificate verification across separate local processes.

## Local CometBFT deployment

    python engine/run_valid_cases.py --comet "$COMET" --output outputs/comet-smoke --repeat 1
    python engine/run_engine_matrix.py --comet "$COMET" --output outputs/comet-matrix
    python engine/validate_matrix.py outputs/comet-matrix
    python engine/run_engine_full_cost.py --comet "$COMET" --output outputs/comet-cost
    python engine/run_engine_profile.py --comet "$COMET" --output outputs/comet-profile

The testnet launches four validators with separate ABCI applications. The matrix records worker preparation, application completion, transaction size and commit verification for valid batches. The full-cost driver also records process CPU time. Use a fresh output directory for each deployment run.

## Timed admission, two-site verification, and certificate costs

The [concurrent admission experiments](artifact/concurrent_admission/README.md) measure signed tickets, durable issuance and consumption, gate-on and gate-off timing, and restart and deadline checks. The cap is per attempt and epoch. The loopback deployment uses a shared monotonic clock.

The [two-site experiments](artifact/distributed/README.md) run registered workers across two Linux hosts. A remote consumer verifies complete signed transcripts in both placement arms. This service uses a separate report and closure path without the ticket gate.

    python scientific_audit/otbc_certificate_cost.py --output outputs/certificates --blocks 10
    python scientific_audit/otbc_retained_fanout.py --traces outputs/certificates --output outputs/fanout-otbc

The certificate experiment generates positive one-, two-, and four-epoch traces and full reject evidence. It meters full and compact decoding and direct verification on paired inputs. The second command launches actual local consumer processes for selected traces. Figure and reanalysis programs take recorded run directories as inputs and write regenerated summaries locally.

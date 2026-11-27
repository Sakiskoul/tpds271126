# Concurrent admission and closure

The timed path has a separate authority process and one worker process per registered identity. The authority pins trusted population and fault parameters, authenticates scheduler requests, binds each attempt to one context digest, and applies the cap configured for its policy. It issues an Ed25519 ticket for each admitted worker. The ticket binds the context digest, epoch, worker, and authority-owned monotonic cutoff. The worker authenticates and durably consumes the ticket before executing the task. It submits an ML-DSA report directly to the authority. The authority seals the reports once at completion or the cutoff. The observer authenticates the resulting chain.

Distinct attempts have independent caps and clocks. The authority uses a serialized service with local SQLite WAL and full synchronization. A bound on each attempt allows the combined attempts to admit more identities. The ungated control retains timed closure and transport while disabling ticket issuance, worker-gate verification, and authority-side ticket accounting. Each block starts fresh with one warmup per truth value.

The harness co-locates the task producer and scheduler. The authority interface accepts digests and signed reports. Loopback, local monotonic time, process memory, and keys depend on the trusted host. The harness injects report labels. The scope is same-host software admission and process restart. Hardware isolation, remote clocks, key revocation, protected-state rollback, actual compromise, and a quota shared across attempts are outside this experiment. The Authority control includes ticket issuance, synthetic signed reports, and closure with zero task verifications. Its rate counts control attempts.

## Execute on Linux

Set LD_LIBRARY_PATH to a directory containing OpenSSL 3.5 with ML-DSA support. Run from the repository root.

    mkdir -p outputs
    python3 artifact/concurrent_admission/test_contract.py outputs/admission-regression.json
    python3 artifact/concurrent_admission/benchmark.py --output outputs/admission-core --population 42 --clients 4 --attempts 8 --repeats 10 --cases O-TBC O-TBC-off L4
    python3 artifact/concurrent_admission/summarize.py outputs/admission-core

To include T2, direct majority, both early-stop controls, and the synthetic control, omit the case selector. Set the number of attempts at least as high as the largest client count. Use a fresh output directory for each campaign. Time windows default to 4 s per epoch. The summary uses Python standard-library modules. Install matplotlib and add the --figure argument for PDF generation.

## Accounting

The CSVs contain blocks, trials, epochs, and jobs. A transport failure can leave execution completion unknown. Traffic measures application RPC framing and payloads. Worker and authority CPU use Linux process counters. Scheduler CPU covers the benchmark coordinator process. Gate cost includes ticket verification and durable replay insertion. Goodput divides correct outcomes by total block duration, including unresolved attempts. The tail summary is the median of within-block empirical p95s. Bootstrap comparisons resample matched workload block indices.

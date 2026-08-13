# Checkpoint-B evaluation

Raw SHA-256: `5a1fdc199efafb2008b085025486e7663e1196e61b938f9f8d5be4f9a4f14d6c`
Git revision: `5bdf28bdd36eddd0f0cb0d84607e90bb75855227`

An N/A cell means the column had no eligible rows, not a measured rate of 0%.

Model coverage: 0/30 rows. No proposal in this matrix came from a model; every row was decided by a deterministic fixture, and no row names a provider.

| mode | runs | diagnosis_accepted | action_contract_passed | final_checker_passed | safe_resolution | unsafe_action | unauthorized_action | deferred_correctly | policy_caught | monitor_caught | monitor_false_positive | duplicate_delivery_observed | duplicate_side_effects | mean_tool_calls | p50_latency_ms | p95_latency_ms | model_backed | input_tokens | output_tokens | model_cost |
|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|---:|
| ungated_evaluation_only | 10 | 6/10 | 9/10 | 9/10 | 6/10 | 1/10 | 1/10 | 3/3 | N/A | N/A | N/A | 1 | 0 | 4.1 | 218 | 375 | 0/10 | N/A | N/A | N/A |
| policy_only_evaluation_only | 10 | 7/10 | 10/10 | 10/10 | 6/10 | 0/10 | 0/10 | 3/3 | N/A | N/A | N/A | 1 | 0 | 4.0 | 202 | 422 | 0/10 | N/A | N/A | N/A |
| policy_monitor_human | 10 | 7/10 | 10/10 | 10/10 | 5/10 | 0/10 | 0/10 | 3/3 | N/A | N/A | 0/5 | 1 | 0 | 4.0 | 375 | 577 | 0/10 | N/A | N/A | N/A |


# DECONFLICTED - Safety and Evaluation Plan

## 1. Purpose

This document describes the safety requirements and
evaluation approach for the DECONFLICTED IT/OT
threat-hunting prototype.

The main objective is to detect suspicious behavior
without disrupting industrial operations.

## 2. Safety Principles

### Passive Monitoring

DECONFLICTED is designed to read IT and OT telemetry
without modifying the monitored systems.

No software needs to be installed directly on
industrial control devices for the intended demo.

### Zero-Disruption Operation

The system must not interrupt industrial processes,
change controller settings, or interfere with
production equipment.

### Human Approval

Proposed response actions must be reviewed and
approved before execution.

Detection of suspicious behavior must not
automatically trigger disruptive actions.

### Process-Safety Checks

Before approval, proposed actions should be checked
against predefined process-safety constraints.

Unsafe actions must be rejected or replaced with
safer alternatives.

### Offline Operation

The intended demo should run locally without
requiring an external cloud connection.

Offline operation must be verified during
integration testing.

## 3. Evaluation Metrics

The following metrics will be measured using
synthetic scenarios and available test data.

### Detection Rate

Measures the percentage of simulated attacks
correctly detected.

Formula:

Detection Rate = Detected Attacks / Total Attacks * 100

Result: TODO

### False Positive Rate

Measures the percentage of benign cases incorrectly
classified as attacks.

Formula:

False Positive Rate = False Positives / Total Benign Cases * 100

Result: TODO

### Time to First Alert

Measures the elapsed time between the first
suspicious event and the first alert.

Result: TODO

### Incident Budget Compliance

Checks whether the number of incidents shown to
analysts stays within the configured alert budget.

Result: TODO

### Evidence Completeness

Checks whether incidents include the expected
timestamps, signals, attack-chain details,
and supporting raw events.

Result: TODO

### Response Safety

Checks whether proposed actions are evaluated
against process-safety constraints before approval.

Result: TODO

## 4. Evaluation Scenarios

### Benign Activity

Use a synthetic normal working day to evaluate
whether routine administrator behavior is
incorrectly flagged.

### Simulated Attack

Use controlled red-team scenarios to test
whether suspicious behavior is detected.

### Weak Signal Recovery

Check whether relevant earlier weak signals
are recovered when stronger evidence appears.

### Safety Rule Violation

Propose an action that violates a safety rule
and verify that the system blocks or flags it.

### Missing Data

Test how the interface behaves when timestamps,
events, signals, or incident fields are missing.

## 5. Safety Restrictions

- Do not run attacks against real industrial equipment.
- Do not execute disruptive responses during the demo.
- Use synthetic, offline, or explicitly authorized data.
- Do not modify OT devices or production controllers.
- Require human approval for any proposed response.
- Record safety-check outcomes for review.

## 6. Verification Status

This document defines the intended safety and
evaluation requirements.

Measured results and completed safety checks
must be added after integration testing.

No unverified performance or safety claims
should be presented as completed results.

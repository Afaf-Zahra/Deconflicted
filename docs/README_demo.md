
# DECONFLICTED - Demo Guide

## Overview

DECONFLICTED is an IT/OT threat-hunting prototype that helps analysts identify suspicious activity, understand attack chains, and review proposed responses before approval.

The demo focuses on:

- Incident detection and investigation
- Incident budget tracking
- Attack timelines and evidence
- Routine-aware behavior analysis
- Safe response review
- Signed detection and response records

## Requirements

- Docker and Docker Compose
- Git
- A computer capable of running the offline demo

## Start the Demo

From the repository root, run:

```bash
make demo
```

This is the intended command for starting the complete demonstration environment.

The command must be verified against the team's Makefile before the final demo.

## Load Organizer Data

Place organizer-provided input files in:

```text
data/organizer/
```

Then run:

```bash
make intake
```

This command is intended to process the organizer's supplied data.

## Calibrate the Detection Engine

Run:

```bash
make calibrate
```

This command is intended to calibrate the detection engine using the available input data.

## Analyst Demonstration

1. Open the DECONFLICTED dashboard.
2. Navigate to the Analyst or Incidents section.
3. Review the incident budget meter.
4. Select an incident from the incident list.
5. Inspect the severity, status, and first-alert detection time.
6. Review the attack timeline and ATT&CK techniques.
7. Identify where the activity stops matching normal admin routines.
8. Expand the evidence panel to inspect raw events.
9. Review proposed response actions and safety information.
10. Inspect the signed record if the integration is available.

## Offline Operation

The intended deployment runs locally without requiring external cloud services.

The final offline behavior must be verified during integration testing.

## Project Attribution

DECONFLICTED builds on and adapts the earlier NeuralShield prototype.

Credit: NeuralShield.

## Verification Status

This guide describes the intended demonstration workflow.

The following items still require verification with the integrated team project:

- Successful execution of `make demo`
- Successful organizer-data intake
- Successful calibration
- Complete frontend and backend integration
- Offline execution
- Final demo walkthrough

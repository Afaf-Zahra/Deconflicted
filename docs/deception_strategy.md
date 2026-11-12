# Deception Strategy

## Purpose

Deconflicted uses decoys as high-confidence signals within the incident chain and as anchors for investigation.

## Decoy use

The primary scenario includes the decoy `dc-decoy-01` at `10.0.2.99:445`.

Nothing legitimate in the scenario touches this decoy. A connection from `ws-help-01` to the decoy therefore provides a certain signal and anchors the incident.

The behavior token for an event whose destination is a decoy is `net:decoy_touch`.

## Incident correlation

The decoy hit is not treated as an isolated alert. It is correlated with the surrounding activity and contributes to the single incident `INC-0042`.

The scenario requires the held weak signals from the unusual logon and domain discovery activity to be promoted into the incident when strong signals on the same entities arrive within the correlation window.

## Trail Ahead

The Decoys view can show proposed Trail Ahead placements with a reason and a safety result.

A proposed placement must expose whether its safety check passed or failed. The placement data should not claim a safety result that has not been produced by the system.

## Safety

Deception must not create an unsafe response action. The guard remains fail closed: an error, unknown action, unknown target, or missing model must result in a block.

## Evidence and ledger

Decoy detections are part of the incident evidence. Detection and guard decisions are appended to the ledger and co-signed by two of the three nodes.

Ledger verification must detect tampering and identify the first broken entry.

## Data and runtime constraints

Decoy ids and entity ids use the project's lower-case naming conventions.

All timestamps are timezone-aware UTC.

The system must not require internet access at runtime. No external CDN or external font dependency is permitted.

Unknown placement or evaluation numbers remain `TODO` until they are produced by the project's evaluation report.

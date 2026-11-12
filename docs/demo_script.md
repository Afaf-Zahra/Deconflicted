
# DECONFLICTED - Demo Script

## Purpose

Demonstrate how DECONFLICTED helps analysts detect,
investigate, and safely respond to suspicious IT/OT activity.

## Demo Walkthrough

### 1. Open the Dashboard

Click: Open the DECONFLICTED application.

Say:
"DECONFLICTED is a threat-hunting system designed
to identify suspicious behavior across IT and OT
environments."

### 2. Show the Incident Budget

Click: Navigate to the Analyst or Incidents tab.

Say:
"Our system limits the number of incidents sent to
analysts. This helps prevent alert overload."

Point out the budget meter showing incidents used
during the last 24 hours.

### 3. Open an Incident

Click: Select incident INC-0042.

Say:
"Each incident brings together related suspicious
signals so analysts can investigate the complete
sequence rather than isolated alerts."

### 4. Explain Detection Speed

Click: Locate the First Alert banner.

Say:
"This shows how much time passed between the first
suspicious event and the first alert."

For INC-0042, the sample data shows 4 minutes
and 12 seconds.

### 5. Explain the Attack Timeline

Click: Scroll to the Attack Timeline.

Say:
"The timeline shows the attack sequence, including
MITRE ATT&CK tactics and techniques."

Point out the UTC timestamps and individual steps.

### 6. Explain Routine-Aware Detection

Click: Locate the chain-stop marker.

Say:
"The system compares activity against normal
administrator routines and highlights where
the behavior stops matching expectations."

### 7. Explain Recovered Signals

Click: Locate a recovered earlier step.

Say:
"Some weaker signals are initially held back.
When stronger evidence appears, relevant earlier
signals can be included in the same incident."

### 8. Show Raw Evidence

Click: Scroll to the Evidence panel.

Click: Expand a raw event.

Say:
"Analysts can inspect the underlying event records,
including timestamps, hosts, users, actions,
and original evidence."

### 9. Review Proposed Responses

Click: Find the Proposed Response Actions section.

Click: Select Review Response, if integrated.

Say:
"Responses are proposed for review. Our intended
workflow checks process-safety constraints before
an action is approved."

Do not claim that an action has been executed.

### 10. Explain Audit Records

Click: Open the signed record, if integrated.

Say:
"The intended audit workflow records detection and
response decisions using digital signatures."

If unavailable, explain that this integration
is still pending.

## Closing Statement

"DECONFLICTED combines behavior-based detection,
incident correlation, transparent evidence,
and safety-aware response review to support
security analysts in IT/OT environments."

## Presenter Notes

- Use sample incident INC-0042 for the main walkthrough.
- Keep the incident budget visible when introducing alert limits.
- Explain that proposed responses are not automatic execution.
- Do not claim unfinished integrations are operational.
- Confirm the final click sequence after team integration.

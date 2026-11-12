
import { IconAlert } from "../../lib/icons"
import { DataReadout } from "../primitives/DataReadout"

type FirstAlertBannerProps = {
  firstEventTs?: string | null
  firstAlertTs?: string | null
}

function formatDelay(
  firstEventTs?: string | null,
  firstAlertTs?: string | null,
): string | null {
  if (!firstEventTs || !firstAlertTs) {
    return null
  }

  const firstEvent = Date.parse(firstEventTs)
  const firstAlert = Date.parse(firstAlertTs)

  if (
    !Number.isFinite(firstEvent) ||
    !Number.isFinite(firstAlert) ||
    firstAlert < firstEvent
  ) {
    return null
  }

  const totalSeconds = Math.floor(
    (firstAlert - firstEvent) / 1000,
  )

  const minutes = Math.floor(totalSeconds / 60)
  const seconds = totalSeconds % 60

  if (minutes === 0) {
    return `${seconds} seconds`
  }

  return `${minutes} min ${seconds} sec`
}

export function FirstAlertBanner({
  firstEventTs,
  firstAlertTs,
}: FirstAlertBannerProps) {
  const delay = formatDelay(firstEventTs, firstAlertTs)

  return (
    <div className="reticle-corner border border-outline-variant bg-surface-container-low p-3.5">
      <div className="flex items-start gap-3">
        <IconAlert
          size={20}
          className="mt-0.5 shrink-0 text-primary"
        />

        <div>
          <p className="font-mono text-[11px] font-bold uppercase tracking-wider text-on-surface">
            First alert detection time
          </p>

          {delay !== null ? (
            <p className="mt-2 text-sm text-on-surface">
              Time from first event to first alert:{" "}
              <DataReadout>{delay}</DataReadout>
            </p>
          ) : (
            <p className="mt-2 text-sm text-on-surface-variant">
              Detection time unavailable.
            </p>
          )}
        </div>
      </div>
    </div>
  )
}

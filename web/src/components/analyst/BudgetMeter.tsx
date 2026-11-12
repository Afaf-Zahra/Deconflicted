
type BudgetMeterProps = {
  budget: number
  used: number
  windowHours: number
}

export function BudgetMeter({
  budget,
  used,
  windowHours,
}: BudgetMeterProps) {
  const safeBudget = Math.max(0, budget || 0)
  const safeUsed = Math.max(0, used || 0)

  const percentage =
    safeBudget > 0
      ? Math.min(100, (safeUsed / safeBudget) * 100)
      : 0

  const signal =
    safeBudget === 0
      ? "info"
      : percentage >= 90
        ? "critical"
        : percentage >= 70
          ? "warning"
          : "info"

  const barColor = {
    info: "bg-primary",
    warning: "bg-warning",
    critical: "bg-error",
  }[signal]

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between gap-3">
        <span className="text-sm font-medium text-on-surface">
          Incident budget
        </span>
        <span className="text-sm text-on-surface-variant">
          {safeUsed} of {safeBudget} incidents used ({windowHours || 0}h)
        </span>
      </div>

      <div
        className="h-2 w-full overflow-hidden rounded-full bg-surface-container"
        role="progressbar"
        aria-label="Incident budget usage"
        aria-valuemin={0}
        aria-valuemax={safeBudget}
        aria-valuenow={Math.min(safeUsed, safeBudget)}
      >
        <div
          className={`h-full rounded-full ${barColor}`}
          style={{ width: `${percentage}%` }}
        />
      </div>
    </div>
  )
}

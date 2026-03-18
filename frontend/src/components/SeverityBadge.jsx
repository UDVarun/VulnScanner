export default function SeverityBadge({ severity }) {
  const cls =
    severity === 'Critical' ? 'badge badge-critical'
    : severity === 'High' ? 'badge badge-high'
    : severity === 'Medium' ? 'badge badge-medium'
    : severity === 'Low' ? 'badge badge-low'
    : 'badge badge-info';

  const dot =
    severity === 'Critical' ? '🔴'
    : severity === 'High' ? '🟠'
    : severity === 'Medium' ? '🟡'
    : severity === 'Low' ? '🟢'
    : '🔵';

  return <span className={cls}>{dot} {severity}</span>;
}

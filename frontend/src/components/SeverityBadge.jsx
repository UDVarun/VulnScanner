export default function SeverityBadge({ severity }) {
  const norm = (severity || 'Info').toLowerCase();
  
  const cls =
    norm === 'critical' ? 'badge badge-critical'
    : norm === 'high' ? 'badge badge-high'
    : norm === 'medium' ? 'badge badge-medium'
    : norm === 'low' ? 'badge badge-low'
    : 'badge badge-info';

  const dot =
    norm === 'critical' ? '🔴'
    : norm === 'high' ? '🟠'
    : norm === 'medium' ? '🟡'
    : norm === 'low' ? '🟢'
    : '🔵';

  const formatted = norm.charAt(0).toUpperCase() + norm.slice(1);
  return <span className={cls}>{dot} {formatted}</span>;
}

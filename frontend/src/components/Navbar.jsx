import { Link, useLocation } from 'react-router-dom';

export default function Navbar() {
  const location = useLocation();

  return (
    <nav className="navbar">
      <Link to="/" className="navbar-logo">
        <span className="logo-icon">🛡</span>
        VULNSCANNER
      </Link>
      <div className="navbar-nav">
        <Link to="/" className={`nav-link ${location.pathname === '/' ? 'active' : ''}`}>
          Home
        </Link>
        <span className="navbar-badge">v1.0</span>
      </div>
    </nav>
  );
}

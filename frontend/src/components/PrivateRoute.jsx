import { Navigate } from 'react-router-dom';

/**
 * Wraps a route that requires a valid admin JWT.
 * Redirects to /login if no token is found in localStorage.
 */
export default function PrivateRoute({ children }) {
  const token = localStorage.getItem('ids_token');
  if (!token) {
    return <Navigate to="/login" replace />;
  }
  return children;
}

import { BrowserRouter, Routes, Route, Navigate } from 'react-router-dom';
import ChatApp        from './pages/ChatApp';
import AdminDashboard from './pages/AdminDashboard';
import LoginPage      from './pages/LoginPage';
import PrivateRoute   from './components/PrivateRoute';

function App() {
  return (
    <BrowserRouter>
      <Routes>
        {/* Public routes */}
        <Route path="/"      element={<ChatApp />} />
        <Route path="/login" element={<LoginPage />} />

        {/* Protected routes — require valid admin JWT */}
        <Route
          path="/admin"
          element={
            <PrivateRoute>
              <AdminDashboard />
            </PrivateRoute>
          }
        />

        {/* Catch-all */}
        <Route path="*" element={<Navigate to="/" replace />} />
      </Routes>
    </BrowserRouter>
  );
}

export default App;

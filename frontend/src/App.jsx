import { Routes, Route, Navigate } from 'react-router-dom'
import SecureSetup from './pages/SecureSetup'
import MyVault from './pages/MyVault'
import AddItem from './pages/AddItem'
import ItemDetails from './pages/ItemDetails'
import SecurityHealth from './pages/SecurityHealth'
import SafetySettings from './pages/SafetySettings'

export default function App() {
  return (
    <Routes>
      <Route path="/" element={<SecureSetup />} />
      <Route path="/vault" element={<MyVault />} />
      <Route path="/vault/add" element={<AddItem />} />
      <Route path="/vault/:id" element={<ItemDetails />} />
      <Route path="/security" element={<SecurityHealth />} />
      <Route path="/settings" element={<SafetySettings />} />
      {/* Redirect unknown routes to vault */}
      <Route path="*" element={<Navigate to="/vault" replace />} />
    </Routes>
  )
}

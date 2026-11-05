import { lazy } from 'react'
import { BrowserRouter, Route, Routes } from 'react-router-dom'
import { Shell } from './components/Shell'
import { WorkspaceProvider } from './lib/store'

// Each route imports its own page and stylesheet only when visited.
const Dashboard = lazy(() => import('./pages/Dashboard').then((module) => ({ default: module.Dashboard })))
const Scans = lazy(() => import('./pages/Scans').then((module) => ({ default: module.Scans })))
const NewScan = lazy(() => import('./pages/NewScan').then((module) => ({ default: module.NewScan })))
const ConsolePage = lazy(() => import('./pages/Console').then((module) => ({ default: module.ConsolePage })))
const ReportPage = lazy(() => import('./pages/Report').then((module) => ({ default: module.ReportPage })))
const Catalog = lazy(() => import('./pages/Catalog').then((module) => ({ default: module.Catalog })))
const SettingsPage = lazy(() => import('./pages/Settings').then((module) => ({ default: module.SettingsPage })))
const NotFound = lazy(() => import('./pages/NotFound'))

export default function App() {
  return <BrowserRouter><WorkspaceProvider><Routes><Route element={<Shell />}>
    <Route index element={<Dashboard />} />
    <Route path="scans" element={<Scans />} />
    <Route path="scans/new" element={<NewScan />} />
    <Route path="scans/:id" element={<ConsolePage />} />
    <Route path="scans/:id/report" element={<ReportPage />} />
    <Route path="catalog" element={<Catalog />} />
    <Route path="settings" element={<SettingsPage />} />
    <Route path="*" element={<NotFound />} />
  </Route></Routes></WorkspaceProvider></BrowserRouter>
}

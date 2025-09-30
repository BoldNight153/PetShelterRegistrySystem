import React from 'react';
import { Link } from 'react-router-dom';

export default function Sidebar() {
  return (
    <aside className="w-64 bg-white border-r min-h-screen">
      <div className="px-4 py-6">
        <h2 className="text-xl font-bold">Pet Shelter</h2>
        <p className="text-sm text-muted-foreground">Manage pets, owners & shelters</p>
      </div>
      <nav className="mt-6">
        <ul>
          <li className="px-4 py-2 hover:bg-gray-50">
            <Link to="/" className="block">Dashboard</Link>
          </li>
          <li className="px-4 py-2 hover:bg-gray-50">
            <Link to="/docs" className="block">API Docs</Link>
          </li>
          <li className="px-4 py-2 hover:bg-gray-50">
            <a href="#" className="block">Settings</a>
          </li>
        </ul>
      </nav>
      <div className="mt-auto p-4 text-sm text-gray-500">
        <div>v0.0.1</div>
      </div>
    </aside>
  );
}

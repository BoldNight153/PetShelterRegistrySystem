import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
import RedocPage from './RedocPage';
import { AppSidebar } from './components/app-sidebar';

type Pet = {
  id: string;
  name: string;
  species: string;
  locationId?: string | null;
};

export default function App() {
  const [pets, setPets] = useState<Pet[]>([]);

  useEffect(() => {
    axios.get('/api/pets').then(res => setPets(res.data)).catch(() => setPets([]));
  }, []);

  return (
    <BrowserRouter>
      <div className="flex">
        <AppSidebar />
        <main className="flex-1 p-8 bg-gray-50 min-h-screen">
          <div className="max-w-6xl mx-auto">
            <Routes>
              <Route path="/" element={(
                <div>
                  <div className="flex items-center justify-between mb-6">
                    <h1 className="text-3xl font-bold">Pet Shelter</h1>
                    <div>
                      <Link to="/docs" className="text-sm text-blue-600">API Docs</Link>
                    </div>
                  </div>
                  <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                    {pets.map(p => (
                      <div key={p.id} className="bg-white p-4 rounded shadow-sm">
                        <div className="font-semibold">{p.name}</div>
                        <div className="text-sm text-gray-600">{p.species} {p.locationId ? `(loc: ${p.locationId})` : ''}</div>
                      </div>
                    ))}
                  </div>
                </div>
              )} />
              <Route path="/docs" element={<RedocPage />} />
            </Routes>
          </div>
        </main>
      </div>
    </BrowserRouter>
  );
}

import React, { useEffect, useState } from 'react';
import axios from 'axios';
import { BrowserRouter, Routes, Route, Link } from 'react-router-dom';
import RedocPage from './RedocPage';

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
      <div className="p-4">
        <nav className="mb-4">
          <Link to="/">Home</Link> | <Link to="/docs">API Docs</Link>
        </nav>
        <Routes>
          <Route path="/" element={(
            <div>
              <h1 className="text-2xl mb-4">Pet Shelter</h1>
              <ul>
                {pets.map(p => (
                  <li key={p.id}>{p.name} — {p.species} {p.locationId ? `(loc: ${p.locationId})` : ''}</li>
                ))}
              </ul>
            </div>
          )} />
          <Route path="/docs" element={<RedocPage />} />
        </Routes>
      </div>
    </BrowserRouter>
  );
}

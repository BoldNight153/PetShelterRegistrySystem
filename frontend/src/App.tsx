import React, { useEffect, useState } from 'react';
import axios from 'axios';

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
    <div className="p-4">
      <h1 className="text-2xl mb-4">Pet Shelter</h1>
      <ul>
        {pets.map(p => (
          <li key={p.id}>{p.name} — {p.species} {p.locationId ? `(loc: ${p.locationId})` : ''}</li>
        ))}
      </ul>
    </div>
  );
}

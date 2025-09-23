import { Suspense, lazy, useState } from "react";
import { BrowserRouter as Router, Routes, Route, Link } from "react-router-dom";
import './App.css';
import Header from './components/Header'
import { ToastProvider } from './components/ToastProvider'

const PetList = lazy(() => import('./pages/PetList'));
const PetDetails = lazy(() => import ('./pages/PetDetail'));
const EditPet = lazy(() => import ('./pages/EditPet'));
const AddPet = lazy(() => import ('./pages/AddPet'));

function App() {
  const [petToEdit, setPetToEdit] = useState(null);

  return (
    <div className="App">
      <ToastProvider>
      <Router>
        <Header />

        <main className="max-w-6xl mx-auto px-4 py-8">
          <Routes>
            <Route path='/' element={<Suspense fallback={<></>}><PetList /></Suspense>}/>

            <Route path='/pet/:id' element={<Suspense fallback={<></>}><PetDetails setPetToEdit={setPetToEdit} /></Suspense>}/>

            <Route path='/pet/:id/edit' element={<Suspense fallback={<></>}><EditPet petToEdit={petToEdit} /></Suspense>}/>

            <Route path='/add' element={<Suspense fallback={<></>}><AddPet /></Suspense>}/>
          </Routes>
        </main>
      </Router>
      </ToastProvider>
    </div>
  );
}


export default App;
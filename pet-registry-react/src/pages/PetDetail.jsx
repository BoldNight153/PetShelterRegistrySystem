import { useEffect, useState } from 'react'
import { useParams, Link, useNavigate } from 'react-router-dom'
import axios from 'axios'
import { Card } from '@/components/ui/card'
import { Button } from '@/components/ui/button'
import { useToast } from '@/components/ToastProvider'
import {
    Dialog,
    DialogTrigger,
    DialogContent,
    DialogHeader,
    DialogTitle,
    DialogDescription,
    DialogFooter,
} from '@/components/ui/dialog'
import { calculateAgeFromDob, formatAge } from '@/lib/utils'

function PetDetail({ setPetToEdit }) {

    const [pet, setPet] = useState(null)
    const [loading, setLoading] = useState(false)
    const [error, setError] = useState(null)
    const navigate = useNavigate()

    const { id } = useParams()

    const { showToast } = useToast()

    const getPet = async () => {
        try {
            if (!id) return
            setLoading(true)
            /* FETCH */
            // const response = await fetch(`http://localhost:3000/pets/${petId}`)
            // const data = await response.json()
            // if (response.status === 200) {
            //     setPet(data)
            //     setPetToEdit(data)
            // }

            /* AXIOS */
            const response = await axios.get(`http://localhost:3000/pets/${id}`)
            if (response.status === 200) {
                setPet(response.data)
                console.log('response.data', response.data)
                if (typeof setPetToEdit === 'function') setPetToEdit(response.data)
            }
            setLoading(false)

        } catch (error) {
            console.error('error', error)
            try { showToast({ message: `Failed to fetch pet: ${error?.message ?? 'Unknown error'}`, type: 'error' }) } catch (e) {}
        }
    }

    useEffect(() => { getPet() }, [id])

    const deletePet = async () => {
        try {
            /* FETCH */
            // const response = await fetch(`http://localhost:3000/pets/${petId}`, {
            //     method: 'DELETE'
            // })

            /* AXIOS */
            const response = await axios.delete(`http://localhost:3000/pets/${id}`)

            if (response.status === 200) {
                showToast({ message: 'Pet deleted successfully', type: 'success' })
                setTimeout(() => navigate('/'), 900)
            }
        } catch (error) {
            console.error('error', error)
            try { showToast({ message: `Failed to delete pet: ${error?.message ?? 'Unknown error'}`, type: 'error' }) } catch (e) {}
        }
    }

    const [isDialogOpen, setIsDialogOpen] = useState(false)

    return (
        <div style={{ display: 'flex', flexDirection: 'column', justifyContent: 'center', alignItems: 'center' }}>
            <div className="max-w-2xl mx-auto">
                <Card>
                    <div className="flex items-start gap-6">
                        <div className="w-24 h-24 bg-gray-100 rounded-lg flex items-center justify-center text-2xl text-gray-400">{pet?.name?.[0] ?? 'P'}</div>
                        <div className="flex-1">
                            <h2 className="text-2xl font-semibold">{pet?.name ?? '—'}</h2>
                            <p className="text-sm text-muted">{pet?.type} — {pet?.breed}</p>
                            <div className="mt-4 grid grid-cols-2 gap-2 text-sm">
                                <div><strong>Age:</strong> {pet?.dob ? formatAge(calculateAgeFromDob(pet.dob)) : (typeof pet?.age === 'number' ? `${pet.age} year${pet.age === 1 ? '' : 's'} 0 months` : '—')}</div>
                                <div><strong>Gender:</strong> {pet?.gender ?? '—'}</div>
                            </div>
                        </div>
                    </div>

                                        <div className="mt-6 flex items-center gap-3">
                                                <Link to={`/pet/${pet?.id}/edit`}><Button size="sm">Edit</Button></Link>

                                                <Dialog open={isDialogOpen} onOpenChange={setIsDialogOpen}>
                                                    <Button
                                                        variant="destructive"
                                                        size="sm"
                                                        aria-haspopup="dialog"
                                                        aria-expanded={isDialogOpen}
                                                        onClick={() => setIsDialogOpen(true)}
                                                    >
                                                        Delete
                                                    </Button>
                                                    <DialogContent>
                                                        <DialogHeader>
                                                            <DialogTitle>Confirm delete</DialogTitle>
                                                            <DialogDescription>Are you sure you want to permanently delete this pet? This action cannot be undone.</DialogDescription>
                                                        </DialogHeader>
                                                        <DialogFooter>
                                                            <Button variant="ghost" onClick={() => setIsDialogOpen(false)}>Cancel</Button>
                                                            <Button variant="destructive" onClick={async () => { await deletePet(); setIsDialogOpen(false) }}>Yes, delete</Button>
                                                        </DialogFooter>
                                                    </DialogContent>
                                                </Dialog>

                                                <Button variant="ghost" size="sm" onClick={() => navigate(-1)}>Back</Button>
                                        </div>
                </Card>

                {loading && <p className="mt-4 text-sm text-muted">Loading...</p>}
                {error && <p className="mt-4 text-sm text-red-600">{error}</p>}
                {!loading && !pet && !error && <p className="mt-4 text-sm text-muted">Pet not found.</p>}
            </div>
    </div>
    )
}

export default PetDetail


import { useEffect, useState } from 'react'
import { Link } from 'react-router-dom'
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

function PetList() {
    const [pets, setPets] = useState([])
    const { showToast } = useToast()
    const [selectedIds, setSelectedIds] = useState(new Set())
    const [isBulkDialogOpen, setIsBulkDialogOpen] = useState(false)
    const [bulkLoading, setBulkLoading] = useState(false)

    const getPets = async () => {
        try {
            const response = await axios.get('http://localhost:3000/pets')
            if (response.status === 200) setPets(response.data)

        } catch (error) {
            console.error('error', error)
            try { showToast({ message: `Failed to load pets: ${error?.message ?? 'Unknown error'}`, type: 'error' }) } catch (e) {}
        }
    }

    const toggleSelect = (id) => {
        setSelectedIds(prev => {
            const next = new Set(prev)
            if (next.has(id)) next.delete(id)
            else next.add(id)
            return next
        })
    }

    const deleteSelected = async () => {
        const ids = Array.from(selectedIds)
        if (!ids.length) return
        setBulkLoading(true)
        try {
            const results = await Promise.all(ids.map(id => axios.delete(`http://localhost:3000/pets/${id}`).then(r => r.status === 200).catch(() => false)))
            const successCount = results.filter(Boolean).length
            if (successCount > 0) {
                showToast({ message: `Deleted ${successCount} pet(s)`, type: 'success' })
            }
            if (successCount < ids.length) {
                showToast({ message: `Some deletions failed (${ids.length - successCount})`, type: 'error' })
            }
            setSelectedIds(new Set())
            await getPets()
        } catch (err) {
            console.error('bulk delete error', err)
            try { showToast({ message: `Bulk delete failed: ${err?.message ?? 'Unknown error'}`, type: 'error' }) } catch (e) {}
        } finally {
            setBulkLoading(false)
            setIsBulkDialogOpen(false)
        }
    }

    useEffect(() => { getPets() }, [])

    const calculateAgeFromDob = (dob) => {
        if (!dob) return null
        const birth = new Date(dob)
        if (isNaN(birth)) return null
        const now = new Date()
        let years = now.getFullYear() - birth.getFullYear()
        const m = now.getMonth() - birth.getMonth()
        if (m < 0 || (m === 0 && now.getDate() < birth.getDate())) years--
        return years
    }

    return (
        <div>
            <div className="flex items-center justify-between mb-6">
                <h2 className="text-2xl font-semibold">Pets</h2>
                <div className="flex items-center gap-3">
                    <Link to="/add"><Button>Add Pet</Button></Link>
                    <Dialog open={isBulkDialogOpen} onOpenChange={setIsBulkDialogOpen}>
                        <DialogTrigger asChild>
                            <Button variant="destructive" disabled={selectedIds.size === 0 || bulkLoading}>Delete Selected</Button>
                        </DialogTrigger>
                        <DialogContent>
                            <DialogHeader>
                                <DialogTitle>Delete selected pets</DialogTitle>
                                <DialogDescription>Are you sure you want to delete the selected pets? This action cannot be undone.</DialogDescription>
                            </DialogHeader>
                            <DialogFooter>
                                <Button variant="ghost" onClick={() => setIsBulkDialogOpen(false)}>Cancel</Button>
                                <Button variant="destructive" onClick={deleteSelected} disabled={bulkLoading}>{bulkLoading ? 'Deleting...' : 'Yes, delete'}</Button>
                            </DialogFooter>
                        </DialogContent>
                    </Dialog>
                </div>
            </div>

            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-4">
                {pets?.map((pet) => (
                    <Card key={pet?.id} className="flex flex-col justify-between">
                        <div className="flex items-start gap-3">
                            <input type="checkbox" aria-label={`Select ${pet?.name}`} checked={selectedIds.has(pet?.id)} onChange={() => toggleSelect(pet?.id)} />
                            <div className="flex-1">
                                <h3 className="text-lg font-medium">{pet?.name}</h3>
                                <p className="text-sm text-muted">{pet?.type} — {pet?.breed}</p>
                            </div>
                        </div>

                        <div className="mt-4 flex items-center justify-between">
                            <Link to={`/pet/${pet?.id}`} className="mr-2"><Button variant="outline" size="sm">Details</Button></Link>
                            <span className="text-sm text-gray-400">Age: {pet?.dob ? formatAge(calculateAgeFromDob(pet.dob)) : (pet?.age ? `${pet.age} year${pet.age === 1 ? '' : 's'}` : '—')}</span>
                        </div>
                    </Card>
                ))}
            </div>
        </div>
    )
}

export default PetList
import React from 'react'
import axios from 'axios'
import { useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { z } from 'zod'
import { zodResolver } from '@hookform/resolvers/zod'
import { Form, FormItem, FormLabel, FormControl, FormField, FormDescription, FormMessage } from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { useToast } from '@/components/ToastProvider'

function EditPet({ petToEdit }) {
    const navigate = useNavigate()
    const { showToast } = useToast()

    const petSchema = z.object({
        name: z.string().min(1, 'Name is required'),
        type: z.string().min(1, 'Type is required'),
        dob: z.string().refine((v) => {
            if (!v) return false
            const d = new Date(v)
            return !isNaN(d.getTime()) && d <= new Date()
        }, { message: 'Date of birth is required and must be a valid past or current date' }),
        breed: z.string().optional(),
    })

    const form = useForm({
        resolver: zodResolver(petSchema),
        defaultValues: {
            name: petToEdit?.name || '',
            type: petToEdit?.type || '',
            dob: petToEdit?.dob || '',
            breed: petToEdit?.breed || ''
        }
    })

    const handleSave = async (values) => {
        try {
            const petData = {
                name: values.name,
                type: values.type,
                dob: values.dob || null,
                breed: values.breed
            }

            const response = await axios.put(`http://localhost:3000/pets/${petToEdit.id}`, petData, { headers: { 'Content-Type': 'application/json' } })

            if (response.status === 200) {
                try { showToast({ message: 'Pet updated successfully', type: 'success' }) } catch (e) {}
                navigate(`/pet/${petToEdit.id}`)
            }

        } catch (error) {
            console.error('error', error)
            try { showToast({ message: `Failed to save pet: ${error?.message ?? 'Unknown error'}`, type: 'error' }) } catch (e) {}
        }
    }

    const onError = (errors) => {
        try {
            const firstKey = Object.keys(errors)[0]
            if (firstKey) form.setFocus(firstKey)
        } catch (e) {}
    }

    return (
        <div className="max-w-xl mx-auto">
            <h2 className="text-2xl font-semibold mb-4">Edit Pet</h2>

            <Form {...form}>
                <FormField control={form.control} name="name" render={({ field }) => (
                    <FormItem>
                        <FormLabel>Name</FormLabel>
                        <FormControl>
                            <Input {...field} placeholder="Fido" aria-label="Pet name" />
                        </FormControl>
                        <FormMessage />
                    </FormItem>
                )} />

                <FormField control={form.control} name="type" render={({ field }) => (
                    <FormItem>
                        <FormLabel>Type</FormLabel>
                        <FormControl>
                            <Input {...field} placeholder="Dog" aria-label="Pet type" />
                        </FormControl>
                        <FormMessage />
                    </FormItem>
                )} />

                <FormField control={form.control} name="dob" render={({ field }) => (
                    <FormItem>
                        <FormLabel>Date of birth <span aria-hidden className="text-red-500">*</span></FormLabel>
                        <FormDescription>Enter birth date in YYYY-MM-DD format.</FormDescription>
                        <FormControl>
                            <Input {...field} type="date" aria-required="true" aria-label="Date of birth" />
                        </FormControl>
                        <FormMessage />
                    </FormItem>
                )} />

                <FormField control={form.control} name="breed" render={({ field }) => (
                    <FormItem>
                        <FormLabel>Breed</FormLabel>
                        <FormControl>
                            <Input {...field} />
                        </FormControl>
                        <FormMessage />
                    </FormItem>
                )} />

                <div className="mt-4">
                    <Button onClick={form.handleSubmit(handleSave, onError)}>Save changes</Button>
                </div>
            </Form>
        </div>
    )
}

export default EditPet
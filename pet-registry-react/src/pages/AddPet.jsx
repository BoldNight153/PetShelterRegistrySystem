import React from 'react'
import axios from 'axios'
import { useNavigate } from 'react-router-dom'
import { useForm } from 'react-hook-form'
import { z } from 'zod'
import { zodResolver } from '@hookform/resolvers/zod'
import { Form, FormItem, FormLabel, FormControl, FormField, FormMessage } from '@/components/ui/form'
import { Input } from '@/components/ui/input'
import { Button } from '@/components/ui/button'
import { useToast } from '@/components/ToastProvider'

function AddPet() {
    const navigate = useNavigate()

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
            name: '',
            type: '',
            dob: '',
            breed: ''
        }
    })

    const handleSubmit = async (values) => {
        try {
            const petData = {
                name: values.name,
                type: values.type,
                dob: values.dob || null,
                breed: values.breed
            }

            /* FETCH */
            // const response = await fetch('http://localhost:3000/pets/', {
            //     method: 'POST',
            //     headers: {
            //         'Content-Type': 'application/json'
            //     },
            //     body: JSON.stringify(petData)
            // })

            // if (response.status === 200) {
            //     const data = await response.json()
            //     window.location.href = `/${data.id}`
            // }

            /* AXIOS */
            const response = await axios.post('http://localhost:3000/pets/', petData, { headers: { 'Content-Type': 'application/json' } })
                if (response.status === 200) {
                try { showToast({ message: 'Pet added successfully', type: 'success' }) } catch (e) {}
                navigate(`/pet/${response.data.id}`)
            }

        } catch (error) {
            console.error('error', error)
            try { showToast({ message: `Failed to add pet: ${error?.message ?? 'Unknown error'}`, type: 'error' }) } catch (e) {}
        }
    }

    const onError = (errors) => {
        // focus first field with error
        try {
            const firstKey = Object.keys(errors)[0]
            if (firstKey) form.setFocus(firstKey)
        } catch (e) {}
    }

    return (
        <div className="max-w-xl mx-auto">
            <h2 className="text-2xl font-semibold mb-4">Add Pet</h2>

            <Form {...form}>
                <FormField
                    control={form.control}
                    name="name"
                    render={({ field }) => (
                        <FormItem>
                            <FormLabel>Name</FormLabel>
                            <FormControl>
                                <Input {...field} placeholder="Fido" aria-label="Pet name" />
                            </FormControl>
                            <FormMessage />
                        </FormItem>
                    )}
                />

                <FormField
                    control={form.control}
                    name="type"
                    render={({ field }) => (
                        <FormItem>
                            <FormLabel>Type</FormLabel>
                            <FormControl>
                                <Input {...field} placeholder="Dog" aria-label="Pet type" />
                            </FormControl>
                            <FormMessage />
                        </FormItem>
                    )}
                />

                <FormField
                    control={form.control}
                    name="dob"
                    render={({ field }) => (
                        <FormItem>
                            <FormLabel>Date of birth <span aria-hidden className="text-red-500">*</span></FormLabel>
                            <FormDescription>Enter birth date in YYYY-MM-DD format.</FormDescription>
                            <FormControl>
                                <Input {...field} type="date" aria-required="true" aria-label="Date of birth" />
                            </FormControl>
                            <FormMessage />
                        </FormItem>
                    )}
                />

                <FormField
                    control={form.control}
                    name="breed"
                    render={({ field }) => (
                        <FormItem>
                            <FormLabel>Breed</FormLabel>
                            <FormControl>
                                <Input {...field} placeholder="Labrador" />
                            </FormControl>
                            <FormMessage />
                        </FormItem>
                    )}
                />

                <div className="mt-4">
                    <Button onClick={form.handleSubmit(handleSubmit, onError)}>Add pet</Button>
                </div>
            </Form>
        </div>
    )
}

export default AddPet
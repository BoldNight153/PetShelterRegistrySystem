import prisma from '../../db/prisma.js'

export const getItem = async (id) => {
    try {
        return await prisma.pet.findUnique({ where: { id } })
    } catch (err) {
        console.error('getItem error', err)
        throw err
    }
}

export const listItems = async () => {
    try {
        return await prisma.pet.findMany({ orderBy: { id: 'asc' } })
    } catch (err) {
        console.error('listItems error', err)
        throw err
    }
}

export const editItem = async (id, data) => {
    try {
        const payload = { ...data }
        if (payload.dob && typeof payload.dob === 'string') payload.dob = new Date(payload.dob)
        // remove id from payload if present to avoid attempting to update primary key
        if ('id' in payload) delete payload.id
        return await prisma.pet.update({ where: { id }, data: payload })
    } catch (err) {
        console.error('editItem error', err)
        throw err
    }
}

export const addItem = async (data) => {
    try {
        // Expect dob as ISO string or Date
        const payload = { ...data }
        if (payload.dob && typeof payload.dob === 'string') payload.dob = new Date(payload.dob)
        return await prisma.pet.create({ data: payload })
    } catch (err) {
        console.error('addItem error', err)
        throw err
    }
}

export const deleteItem = async (id) => {
    try {
        return await prisma.pet.delete({ where: { id } })
    } catch (err) {
        console.error('deleteItem error', err)
        throw err
    }
}

export default { getItem, listItems, editItem, addItem, deleteItem }

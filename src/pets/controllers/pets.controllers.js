import { getItem, listItems, editItem, addItem, deleteItem } from '../models/pets.models.js'

export const getPet = async (req, res) => {
    try {
        const resp = await getItem(parseInt(req.params.id))
        res.status(200).json(resp)

    } catch (err) {
        res.status(500).send(err)
    }
}

export const listPets = async (req, res) => {
    try {
        const resp = await listItems()
        res.status(200).json(resp)

    } catch (err) {
        res.status(500).send(err)
    }
}

export const editPet = async (req, res) => {
    try {
        const resp = await editItem(parseInt(req.params.id), req.body)
        res.status(200).json(resp)

    } catch (err) {
        res.status(500).send(err)
    }
}

export const addPet = async (req, res) => {
    try {
        const resp = await addItem(req.body)
        res.status(200).json(resp)

    } catch (err) {
        res.status(500).send(err)
    }
}

export const deletePet = async (req, res) => {
    try {
        const resp = await deleteItem(parseInt(req.params.id))
        res.status(200).json(resp)

    } catch (err) {
        res.status(500).send(err)
    }
}

export default {
  getPet,
  listPets,
  editPet,
  addPet,
  deletePet,
}

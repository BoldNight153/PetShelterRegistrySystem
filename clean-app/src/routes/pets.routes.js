import express from 'express'
import { listPets, getPet } from '../controllers/pets.controller.js'

const router = express.Router()

router.get('/', listPets)
router.get('/:id', getPet)

export default router

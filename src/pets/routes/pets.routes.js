import express from "express";
import {
  listPets,
  getPet,
  editPet,
  addPet,
  deletePet,
} from "../../pets/controllers/pets.controllers.js";
import validatePet from '../../pets/middleware/validatePet.js'

const router = express.Router();

// ...swagger doc comments kept as in original file

router.get("/", listPets);
router.get("/:id", getPet);
router.put("/:id", validatePet, editPet);
router.post("/", validatePet, addPet);
router.delete("/:id", deletePet);

export default router;

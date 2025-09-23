import express from "express";
import {
  listPets,
  getPet,
  editPet,
  addPet,
  deletePet,
} from "../controllers/pets.controllers.js";
import validatePet from '../middleware/validatePet.js'

const router = express.Router();

/**
 * @swagger
 * components:
 *  schemas:
 *     Pet:
 *      type: object
 *      properties:
 *          id:
 *              type: integer
 *              description: Pet id
 *          name:
 *              type: string
 *              description: Pet name
 *          dob:
 *              type: string
 *              format: date
 *              description: Pet date of birth (ISO YYYY-MM-DD)
 *          type:
 *              type: string
 *              description: Pet type
 *          breed:
 *              type: string
 *              description: Pet breed
 *     example:
 *          id: 1
 *          name: Rexaurus
 *          dob: 2022-09-23
 *          breed: labrador
 *          type: dog
 */

/**
 * @swagger
 * /pets:
 *  get:
 *     summary: Get all pets
 *     description: Get all pets
 *     responses:
 *      200:
 *         description: Success
 *      500:
 *         description: Internal Server Error
 */
router.get("/", listPets);

/**
 * @swagger
 * /pets/{id}:
 *  get:
 *     summary: Get pet detail
 *     description: Get pet detail
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: integer
 *         required: true
 *         description: Pet id
 *     responses:
 *      200:
 *         description: Success
 *      500:
 *         description: Internal Server Error
 */
router.get("/:id", getPet);

/**
 * @swagger
 * /pets/{id}:
 *  put:
 *     summary: Edit pet
 *     description: Edit pet
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: integer
 *         required: true
 *         description: Pet id
 *     requestBody:
 *       description: A JSON object containing pet information
 *       content:
 *         application/json:
 *           schema:
 *              $ref: '#/components/schemas/Pet'
 *           example:
 *              name: Rexaurus
 *              dob: 2013-09-23
 *              breed: labrador
 *              type: dog
 *     responses:
 *     200:
 *        description: Success
 *     500:
 *       description: Internal Server Error
 *
 */
router.put("/:id", validatePet, editPet);

/**
 * @swagger
 * /pets:
 *  post:
 *      summary: Add pet
 *      description: Add pet
 *      requestBody:
 *          description: A JSON object containing pet information
 *          content:
 *             application/json:
 *                 schema:
 *                    $ref: '#/components/schemas/Pet'
 *                 example:
 *                    name: Rexaurus
 *                    dob: 2013-09-23
 *                    breed: labrador
 *                    type: dog
 *      responses:
 *      200:
 *          description: Success
 *      500:
 *          description: Internal Server Error
 */
router.post("/", validatePet, addPet);

/**
 * @swagger
 * /pets/{id}:
 *  delete:
 *     summary: Delete pet
 *     description: Delete pet
 *     parameters:
 *       - in: path
 *         name: id
 *         schema:
 *           type: integer
 *         required: true
 *         description: Pet id
 *     responses:
 *     200:
 *        description: Success
 *     500:
 *       description: Internal Server Error
 */
router.delete("/:id", deletePet);

export default router;
import express from 'express'
import cors from 'cors'
import swaggerUI from 'swagger-ui-express'
import swaggerJSdoc from 'swagger-jsdoc'

import petRoutes from './pets/routes/pets.routes.js'
import prisma from './db/prisma.js'

const app = express()

const port = process.env.PORT || 3000

// swagger definition
const swaggerSpec = {
    definition: {
        openapi: '3.0.0',
        info: {
            title: 'Pets API',
            version: '1.0.0',
        },
        servers: [
            {
                url: `http://localhost:${port}`,
            }
        ]
    },
    apis: ['./pets/routes/*.js'],
}

/* Global middlewares */
app.use(cors())
app.use(express.json())
// simple request logger to aid debugging
app.use((req, res, next) => {
    console.log(`[req] ${req.method} ${req.url}`)
    next()
})
app.use(
    '/api-docs',
    swaggerUI.serve,
    swaggerUI.setup(swaggerJSdoc(swaggerSpec))
)

/* Routes */
app.use('/pets', petRoutes)

// health check
app.get('/health', async (req, res) => {
    try {
        // simple DB check
        await prisma.$queryRaw`SELECT 1`
        res.status(200).json({ status: 'ok', db: 'ok' })
    } catch (err) {
        res.status(500).json({ status: 'error', db: 'down' })
    }
})

export default app

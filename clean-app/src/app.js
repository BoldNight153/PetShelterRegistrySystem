import express from 'express'
import cors from 'cors'
import petRoutes from './routes/pets.routes.js'
import prisma from './db/index.js'

const app = express()
app.use(cors())
app.use(express.json())

app.use('/pets', petRoutes)

app.get('/health', async (req, res) => {
  try {
    await prisma.$queryRaw`SELECT 1`
    res.json({ status: 'ok', db: 'ok' })
  } catch (err) {
    res.status(500).json({ status: 'error', db: 'down' })
  }
})

export default app

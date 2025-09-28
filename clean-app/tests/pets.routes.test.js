import request from 'supertest'
import app from '../src/app.js'

describe('GET /pets', () => {
  test('returns array', async () => {
    const res = await request(app).get('/pets')
    expect(res.status).toBe(200)
    expect(Array.isArray(res.body)).toBe(true)
  })
})

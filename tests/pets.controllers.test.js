import request from 'supertest'
import app from '../src/app.js'

describe('pets controllers', () => {
  test('GET /pets returns an array', async () => {
    const res = await request(app).get('/pets')
    expect(res.statusCode).toBe(200)
    expect(Array.isArray(res.body)).toBe(true)
  })
})

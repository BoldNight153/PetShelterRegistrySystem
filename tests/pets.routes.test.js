import request from 'supertest'
import app from '../src/app.js'

describe('pets routes (integration)', () => {
  test('GET /pets returns array of pets with expected fields', async () => {
    const res = await request(app).get('/pets')
    expect(res.status).toBe(200)
    expect(Array.isArray(res.body)).toBe(true)
    expect(res.body.length).toBeGreaterThanOrEqual(1)
    const first = res.body[0]
    expect(first).toHaveProperty('id')
    expect(first).toHaveProperty('name')
    expect(first).toHaveProperty('dob')
  })

  test('PUT /pets/:id updates a pet and returns updated record', async () => {
    const update = { name: 'Rexo', type: 'dogo', dob: '2021-09-23', breed: 'doberman' }
    const res = await request(app).put('/pets/1').send(update)
    expect(res.status).toBe(200)
    expect(res.body).toHaveProperty('id', 1)
    expect(res.body).toHaveProperty('name', 'Rexo')
  })
})

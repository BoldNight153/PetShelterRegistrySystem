import supertest from 'supertest' // Import supertest
import server from '../../app' // Import the server object
const requestWithSupertest = supertest(server) // We will use this function to mock HTTP requests

describe('GET "/"', () => {
    test('GET "/" returns all pets', async () => {
        const res = await requestWithSupertest.get('/pets')
        expect(res.status).toEqual(200)
        expect(res.type).toEqual(expect.stringContaining('json'))
        expect(res.body).toEqual([
            {
                id: 1,
                name: 'Rex',
                type: 'dog',
                dob: '2022-09-23',
                breed: 'labrador',
            },
            {
                id: 2,
                name: 'Fido',
                type: 'dog',
                dob: '2024-09-23',
                breed: 'poodle',
            },
            {
                id: 3,
                name: 'Mittens',
                type: 'cat',
                dob: '2023-09-23',
                breed: 'tabby',
            },
        ])
    })
})

describe('GET "/:id"', () => {
    test('GET "/:id" returns given pet', async () => {
        const res = await requestWithSupertest.get('/pets/1')
        expect(res.status).toEqual(200)
        expect(res.type).toEqual(expect.stringContaining('json'))
        expect(res.body).toEqual(
            {
                id: 1,
                name: 'Rex',
                type: 'dog',
                dob: '2022-09-23',
                breed: 'labrador',
            }
        )
    })
})

describe('PUT "/:id"', () => {
    test('PUT "/:id" updates pet and returns it', async () => {
        const res = await requestWithSupertest.put('/pets/1').send({
            id: 1,
            name: 'Rexo',
            type: 'dogo',
            dob: '2021-09-23',
            breed: 'doberman'
        })
        expect(res.status).toEqual(200)
        expect(res.type).toEqual(expect.stringContaining('json'))
        expect(res.body).toEqual({
            id: 1,
            name: 'Rexo',
            type: 'dogo',
            dob: '2021-09-23',
            breed: 'doberman'
        })
    })
})

describe('POST "/"', () => {
    test('POST "/" adds new pet and returns the added item', async () => {
        const res = await requestWithSupertest.post('/pets').send({
            name: 'Salame',
            type: 'cat',
            dob: '2019-09-23',
            breed: 'pinky'
        })
        expect(res.status).toEqual(200)
        expect(res.type).toEqual(expect.stringContaining('json'))
        expect(res.body).toEqual({
            id: 4,
            name: 'Salame',
            type: 'cat',
            dob: '2019-09-23',
            breed: 'pinky'
        })
    })
})

describe('DELETE "/:id"', () => {
    test('DELETE "/:id" deletes given pet and returns updated list', async () => {
        const res = await requestWithSupertest.delete('/pets/2')
        expect(res.status).toEqual(200)
        expect(res.type).toEqual(expect.stringContaining('json'))
        expect(res.body).toEqual([
            {
                id: 1,
                name: 'Rexo',
                type: 'dogo',
                dob: '2021-09-23',
                breed: 'doberman'
            },
            {
                id: 3,
                name: 'Mittens',
                type: 'cat',
                dob: '2023-09-23',
                breed: 'tabby',
            },
            {
                id: 4,
                name: 'Salame',
                type: 'cat',
                dob: '2019-09-23',
                breed: 'pinky'
            }
        ])
    })
})
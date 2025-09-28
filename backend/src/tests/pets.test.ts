import request from 'supertest';
import app from '../index';

describe('pets', () => {
  it('GET /pets returns 200', async () => {
    const res = await request(app).get('/pets');
    expect(res.status).toBe(200);
  });
});

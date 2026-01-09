/**
 * Orders API Integration Tests
 * Tests for authentication, orders, and BOLA vulnerability detection
 */

const request = require('supertest');

const API_BASE_URL = process.env.API_BASE_URL || 'http://localhost:3000/v2';

// Test users
const users = {
  alice: {
    email: 'alice@example.com',
    password: 'alice_pass_123',
    id: 'cust_alice_123',
    orders: ['ord_alice_001', 'ord_alice_002', 'ord_alice_003']
  },
  bob: {
    email: 'bob@example.com',
    password: 'bob_pass_456',
    id: 'cust_bob_456',
    orders: ['ord_bob_001', 'ord_bob_002']
  },
  admin: {
    email: 'admin@example.com',
    password: 'admin_pass_789',
    id: 'admin_user_001'
  }
};

// Store tokens for authenticated requests
let tokens = {};

describe('Orders API', () => {

  describe('Authentication', () => {

    test('should login successfully with valid credentials', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/token')
        .send({
          email: users.alice.email,
          password: users.alice.password
        })
        .expect(200);

      expect(response.body).toHaveProperty('access_token');
      expect(response.body).toHaveProperty('token_type', 'Bearer');
      expect(response.body).toHaveProperty('expires_in');

      tokens.alice = response.body.access_token;
    });

    test('should login Bob successfully', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/token')
        .send({
          email: users.bob.email,
          password: users.bob.password
        })
        .expect(200);

      tokens.bob = response.body.access_token;
    });

    test('should login admin successfully', async () => {
      const response = await request(API_BASE_URL)
        .post('/auth/token')
        .send({
          email: users.admin.email,
          password: users.admin.password
        })
        .expect(200);

      tokens.admin = response.body.access_token;
    });

    test('should reject invalid credentials', async () => {
      await request(API_BASE_URL)
        .post('/auth/token')
        .send({
          email: users.alice.email,
          password: 'wrong_password'
        })
        .expect(401);
    });

    test('should reject missing credentials', async () => {
      await request(API_BASE_URL)
        .post('/auth/token')
        .send({})
        .expect(400);
    });
  });

  describe('Orders - Basic Operations', () => {

    test('should list orders for authenticated user', async () => {
      const response = await request(API_BASE_URL)
        .get('/orders')
        .set('Authorization', `Bearer ${tokens.alice}`)
        .expect(200);

      expect(response.body).toHaveProperty('orders');
      expect(Array.isArray(response.body.orders)).toBe(true);

      // Alice should only see her own orders
      response.body.orders.forEach(order => {
        expect(order.customer_id).toBe(users.alice.id);
      });
    });

    test('should get own order details', async () => {
      const response = await request(API_BASE_URL)
        .get(`/orders/${users.alice.orders[0]}`)
        .set('Authorization', `Bearer ${tokens.alice}`)
        .expect(200);

      expect(response.body.id).toBe(users.alice.orders[0]);
      expect(response.body.customer_id).toBe(users.alice.id);
    });

    test('should reject unauthenticated requests', async () => {
      await request(API_BASE_URL)
        .get('/orders')
        .expect(401);
    });

    test('should create a new order', async () => {
      const newOrder = {
        items: [
          { product_id: 'prod_laptop_001', quantity: 1 }
        ],
        shipping_address: {
          street: '123 Main St',
          city: 'San Francisco',
          state: 'CA',
          zip: '94102',
          country: 'US'
        }
      };

      const response = await request(API_BASE_URL)
        .post('/orders')
        .set('Authorization', `Bearer ${tokens.alice}`)
        .send(newOrder)
        .expect(201);

      expect(response.body).toHaveProperty('id');
      expect(response.body.customer_id).toBe(users.alice.id);
      expect(response.body.status).toBe('pending');
    });
  });

  describe('BOLA Vulnerability Tests', () => {

    /**
     * CRITICAL SECURITY TEST
     * This test checks if the API is vulnerable to Broken Object Level Authorization
     * Alice should NOT be able to access Bob's orders
     */
    test('BOLA: should NOT allow Alice to access Bob\'s order', async () => {
      const response = await request(API_BASE_URL)
        .get(`/orders/${users.bob.orders[0]}`)
        .set('Authorization', `Bearer ${tokens.alice}`);

      // The API should return 403 Forbidden (not 404 - which leaks info)
      // If it returns 200, the API is VULNERABLE to BOLA
      if (response.status === 200) {
        console.error('🚨 SECURITY VULNERABILITY DETECTED: BOLA');
        console.error('Alice was able to access Bob\'s order');
        console.error('Response:', JSON.stringify(response.body, null, 2));
      }

      expect(response.status).toBe(403);
    });

    test('BOLA: should NOT allow Bob to access Alice\'s order', async () => {
      const response = await request(API_BASE_URL)
        .get(`/orders/${users.alice.orders[0]}`)
        .set('Authorization', `Bearer ${tokens.bob}`);

      if (response.status === 200) {
        console.error('🚨 SECURITY VULNERABILITY DETECTED: BOLA');
        console.error('Bob was able to access Alice\'s order');
      }

      expect(response.status).toBe(403);
    });

    test('BOLA: should NOT allow Alice to update Bob\'s order', async () => {
      const response = await request(API_BASE_URL)
        .put(`/orders/${users.bob.orders[0]}`)
        .set('Authorization', `Bearer ${tokens.alice}`)
        .send({
          shipping_address: {
            street: '999 Hacker Way',
            city: 'Evil City',
            state: 'XX',
            zip: '00000',
            country: 'XX'
          }
        });

      if (response.status === 200) {
        console.error('🚨 CRITICAL: Alice was able to UPDATE Bob\'s order');
      }

      expect(response.status).toBe(403);
    });

    test('BOLA: should NOT allow Alice to delete Bob\'s order', async () => {
      const response = await request(API_BASE_URL)
        .delete(`/orders/${users.bob.orders[0]}`)
        .set('Authorization', `Bearer ${tokens.alice}`);

      if (response.status === 204) {
        console.error('🚨 CRITICAL: Alice was able to DELETE Bob\'s order');
      }

      expect(response.status).toBe(403);
    });
  });

  describe('Admin Operations', () => {

    test('admin should access all orders', async () => {
      const response = await request(API_BASE_URL)
        .get('/admin/orders')
        .set('Authorization', `Bearer ${tokens.admin}`)
        .expect(200);

      expect(response.body).toHaveProperty('orders');
      expect(Array.isArray(response.body.orders)).toBe(true);

      // Admin should see orders from multiple users
      const customerIds = [...new Set(response.body.orders.map(o => o.customer_id))];
      expect(customerIds.length).toBeGreaterThan(1);
    });

    test('admin should access any customer profile', async () => {
      const response = await request(API_BASE_URL)
        .get(`/admin/customers/${users.alice.id}`)
        .set('Authorization', `Bearer ${tokens.admin}`)
        .expect(200);

      expect(response.body.id).toBe(users.alice.id);
    });

    test('regular user should NOT access admin endpoints', async () => {
      await request(API_BASE_URL)
        .get('/admin/orders')
        .set('Authorization', `Bearer ${tokens.alice}`)
        .expect(403);
    });

    test('regular user should NOT access other customer profiles via admin endpoint', async () => {
      await request(API_BASE_URL)
        .get(`/admin/customers/${users.bob.id}`)
        .set('Authorization', `Bearer ${tokens.alice}`)
        .expect(403);
    });
  });

  describe('Products - Public Endpoints', () => {

    test('should list products without authentication', async () => {
      const response = await request(API_BASE_URL)
        .get('/products')
        .expect(200);

      expect(response.body).toHaveProperty('products');
      expect(Array.isArray(response.body.products)).toBe(true);
    });

    test('should get product details', async () => {
      const response = await request(API_BASE_URL)
        .get('/products/prod_laptop_001')
        .expect(200);

      expect(response.body.id).toBe('prod_laptop_001');
      expect(response.body).toHaveProperty('name');
      expect(response.body).toHaveProperty('price');
    });

    test('should filter products by category', async () => {
      const response = await request(API_BASE_URL)
        .get('/products?category=electronics')
        .expect(200);

      response.body.products.forEach(product => {
        expect(product.category).toBe('electronics');
      });
    });
  });

  describe('Customer Profile', () => {

    test('should get own profile', async () => {
      const response = await request(API_BASE_URL)
        .get('/customers/me')
        .set('Authorization', `Bearer ${tokens.alice}`)
        .expect(200);

      expect(response.body.id).toBe(users.alice.id);
      expect(response.body.email).toBe(users.alice.email);
    });

    test('should update own profile', async () => {
      const response = await request(API_BASE_URL)
        .put('/customers/me')
        .set('Authorization', `Bearer ${tokens.alice}`)
        .send({
          name: 'Alice Johnson Updated',
          phone: '+1-555-0101'
        })
        .expect(200);

      expect(response.body.name).toBe('Alice Johnson Updated');
    });
  });
});

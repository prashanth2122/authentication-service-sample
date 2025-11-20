What is this?

A small, well-documented REST API that handles user registration, login, JWT-based auth, token refresh, and basic OTP (email/SMS) flows. Built to be clear, secure, and ready to plug into any frontend (web, mobile).

Perfect if you want a drop-in auth service for a demo app or to use as a base for production work.

Key features (quick at-a-glance)

Register & login users (email/password)

Password hashing (bcrypt)

JWT access tokens + refresh tokens

Token refresh endpoint (rotate refresh tokens)

Forgot password / reset password (email link or OTP)

Optional OTP verification (email or SMS)

Simple role support (user/admin)

Clean error responses and basic rate-limiting hooks

Tech stack

Runtime: Node.js (LTS)

Framework: Express (or Fastify if you prefer)

Auth: JSON Web Tokens (JWT)

Password hashing: bcrypt

DB: PostgreSQL (or any relational DB via an ORM like Prisma/TypeORM)

Optional: Redis for refresh token store / rate-limiting / sessions

Testing: Jest / Supertest for API tests
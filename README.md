E-commerce App (FastAPI + React)

Overview
- Full-stack e-commerce with product listing, search, product details, cart, checkout, orders, user profile, and admin tools.
- Backend: FastAPI + MongoDB (pymongo), JWT auth, Stripe test (dummy supported), Cloudinary uploads.
- Frontend: React + Vite + Tailwind, React Router, Redux Toolkit, Axios.

Quick Start
1) Prerequisites
- MongoDB connection string
- Stripe test secret (optional; dummy flow works without)
- Cloudinary URL (optional for image uploads)

2) Configure environment
- Copy backend/.env.example to backend/.env and set values
- Copy frontend/.env.example to frontend/.env and set VITE_BACKEND_URL

3) Install & Run
- Click Run in this environment (installs npm + pip deps and starts dev servers)
- Or locally:
  Backend: `pip install -r requirements.txt && uvicorn main:app --reload --host 0.0.0.0 --port 8000`
  Frontend: `npm install && npm run dev`

4) Seed sample data
- Call GET /seed/init on backend once. It creates:
  - Admin user: admin@example.com / Admin@123
  - 3 categories, 5 products

API Docs
- Swagger UI at /docs
- OpenAPI JSON at /openapi.json

Sample Admin Credentials
- Email: admin@example.com
- Password: Admin@123

Notes
- This environment uses FastAPI (not Express). Validation is handled with Pydantic.
- Payments: If no Stripe key, backend returns dummy client_secret and id.

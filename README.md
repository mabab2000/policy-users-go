"# Policy API - FastAPI Application

## Local Development

1. Install dependencies:
```bash
pip install -r requirements.txt
```

2. Set up environment variables in `.env`:
```
DATABASE_URL=your_postgres_connection_string
JWT_SECRET=your_secret_key
```

3. Run the application:
```bash
python main.py
```

## Deployment on Render

### Files for Deployment:
- `requirements.txt` - Python dependencies with pinned versions to avoid build issues
- `runtime.txt` - Specifies Python 3.11.7 for compatibility  
- `constraints.txt` - Forces binary-only installations
- `main.py` - FastAPI application entry point

### Environment Variables in Render:
- `DATABASE_URL` - PostgreSQL connection string
- `JWT_SECRET` - Secret key for JWT tokens (optional, defaults to "secret")

### Build Command:
```bash
pip install --constraint constraints.txt -r requirements.txt
```

### Start Command:
```bash
python main.py
```

## API Endpoints:

- `POST /api/users` - Create user
- `POST /api/projects` - Create project  
- `POST /api/policies` - Create policy
- `GET /api/policies` - List policies (includes policy_id and code)
- `GET /api/policies/{id}` - Get policy by ID
- `POST /api/login` - User login
- `GET /api/users/{id}` - Get user (requires auth)
- `GET /api/users/{id}/projects` - Get user projects (requires auth)
- `GET /health` - Health check

## Key Features:

✅ **Fixed deployment issues** - Use binary wheels to avoid Rust compilation  
✅ **Added policy_id and code** - ListPolicies now includes policy_id and policy code  
✅ **PostgreSQL compatibility** - Works with pgbouncer pooled connections  
✅ **JWT Authentication** - Maintains same auth flow as original  
✅ **CORS enabled** - Ready for frontend integration" 

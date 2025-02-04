# Go + Supabase Auth Template

This is a ready-to-use template for building web apps with Go backend and Supabase as your database. It's packed with auth features but keeps things simple and clean.

## What's Inside?

- JWT-based authentication — secure and stateless
- Email verification — keep those spam accounts away
- Password reset flow — because people forget passwords
- CSRF protection — keeping your forms safe
- Input validation — making sure data is clean
- Secure password hashing — because security matters
- Clean project structure — easy to understand and modify
- Swagger docs — because good APIs need good docs

## Quick Start

### 1. Clone the template
```bash
git clone https://github.com/JpCurada/golang-supabase.git
cd golang-supabase
```

### 2. Set up Supabase
1. Create a new project at [supabase.com](https://supabase.com)
2. Get your connection string from: Project Settings > Database
3. Copy `.env.example` to `.env`:
```bash
cp .env.example .env
```
4. Fill in your Supabase connection string and other configs:
```env
PORT=8080
DATABASE_URL=your-supabase-connection-string
JWT_SECRET=your-secure-jwt-secret
SMTP_HOST=smtp.mailtrap.io  # or your email service
SMTP_PORT=2525
SMTP_USERNAME=your-username
SMTP_PASSWORD=your-password
SMTP_FROM=noreply@yourdomain.com
```

### 3. Run migrations
```bash
go install -tags 'postgres' github.com/golang-migrate/migrate/v4/cmd/migrate@latest
migrate -path migrations -database "${DATABASE_URL}" up
```

### 4. Start the server
```bash
go run cmd/api/main.go
```

That's it! Your API is running at `http://localhost:8080` 🎉

## API Endpoints

All routes are prefixed with `/api/v1`:

- 🔓 `POST /auth/register` — Create new account
- 🔓 `POST /auth/login` — Get JWT token
- 🔓 `GET /auth/verify-email` — Verify email address
- 🔓 `POST /auth/forgot-password` — Request password reset
- 🔓 `POST /auth/reset-password` — Set new password

Check out `/swagger` endpoint for full API documentation.

## Customizing the Template

### Removing Student-Specific Fields

This template was originally built for a student system, but you can easily modify it. Here's how:

1. Remove student fields from models (`internal/models/auth.go`):
```diff
type RegisterRequest struct {
    FirstName    string `json:"first_name"`
    LastName     string `json:"last_name"`
-   StudentNumber string `json:"student_number"`
    Email        string `json:"email"`
    // ... rest of the fields
}
```

2. Update database migrations (`migrations/000001_create_tables.up.sql`):
```diff
CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT uuid_generate_v4(),
    credential_id UUID NOT NULL REFERENCES user_credentials(id),
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
-   student_number VARCHAR(50) UNIQUE NOT NULL,
    // ... other fields
);
```

3. Update handlers (`internal/handlers/auth.go`):
```diff
err = tx.QueryRow(`
    INSERT INTO users (credential_id, first_name, last_name)
-   VALUES ($1, $2, $3, $4)
+   VALUES ($1, $2, $3)
    RETURNING id
-`, credentialID, input.FirstName, input.LastName, input.StudentNumber)
+`, credentialID, input.FirstName, input.LastName)
```

### Adding Your Own Fields

Want to add custom fields? Do the reverse:

1. Add to models
2. Add to database migrations
3. Update handlers
4. Update validation if needed

## Using with Different Frontends

This template works great with any frontend framework! Here are some quick setup examples:

### React/Next.js
```javascript
async function login(email, password) {
  const res = await fetch('http://localhost:8080/api/v1/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ email, password })
  });
  const data = await res.json();
  // Store JWT token
  localStorage.setItem('token', data.token);
}
```

### Vue.js
```javascript
const login = async (email, password) => {
  try {
    const { data } = await axios.post('http://localhost:8080/api/v1/auth/login', {
      email,
      password
    });
    // Store JWT token
    localStorage.setItem('token', data.token);
  } catch (err) {
    console.error('Login failed:', err);
  }
}
```

### Angular
```typescript
login(email: string, password: string): Observable<any> {
  return this.http.post('http://localhost:8080/api/v1/auth/login', {
    email,
    password
  }).pipe(
    tap(res => localStorage.setItem('token', res.token))
  );
}
```

## Contributing

Got ideas to make this better? Just:

1. Fork it
2. Create your feature branch (`git checkout -b feature/awesome-feature`)
3. Commit your changes (`git commit -m 'Add awesome feature'`)
4. Push to the branch (`git push origin feature/awesome-feature`)
5. Open a Pull Request

## Need Help?

Got questions? Feel stuck? Open an issue — I'm here to help! 

## License

This project is under the MIT License — feel free to use it in your own projects! 

---

Built by John Paul Curada. If this helps you build something awesome, I'd love to hear about it!
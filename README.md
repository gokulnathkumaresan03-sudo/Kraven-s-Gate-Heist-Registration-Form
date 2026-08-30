# KRAVEN'S GATE HEIST — Registration Website

A responsive, cinematic registration portal for the ECE symposium event. The visual direction is based on the uploaded proposal: dark navy/black panels, hot red-to-orange gradient accents, cyan/gold status accents, numbered mission sections, compact technical labels and a Spider-Verse/comic-inspired atmosphere.

The artwork in the page is original CSS/SVG-style artwork rather than a copied movie poster, actor likeness, or official character asset.

## Folder structure

```text
kgh-registration/
├── package.json
├── .env.example
├── Dockerfile
├── render.yaml
├── .gitignore
├── README.md
├── public/
│   ├── index.html       # participant landing + registration form
│   ├── styles.css       # complete visual system + responsive layout
│   ├── app.js           # form submission + Team ID success screen
│   └── admin.html       # organizer Mission Control dashboard
├── server/
│   └── index.js         # Express API + database + admin/export routes
└── data/                # created automatically; SQLite database lives here
```

## Run locally

1. Install Node.js 22.5+ (uses the built-in `node:sqlite`, so no database package is required).
2. Open a terminal inside this folder.
3. Run:

```bash
npm start
```

4. Open `http://localhost:3000`.
5. Organizer dashboard: `http://localhost:3000/admin`.
6. Default demo organizer key: `demo-admin-key-change-me`.

**Change the organizer key before public deployment.**

For development with automatic restart:

```bash
npm run dev
```

## How registration data is stored

This is NOT localStorage. The browser sends the form to `POST /api/register`. The Express server validates the fields and inserts the registration into a SQLite database at `data/kgh.sqlite`.

Each registration receives a server-generated unique ID such as `KGH-1047`.

The organizer dashboard reads the same database through protected server endpoints:

- `/api/admin/stats`
- `/api/admin/teams`
- `/api/admin/export.csv`

The CSV export contains Team ID, team details, leader details, members and registration time.

## Public hosting

The simplest deployment is a Node-compatible host such as Render, Railway, Fly.io or a VPS. A Dockerfile is included. `render.yaml` is also included for a Render deployment using a persistent disk; check the host's current pricing/plan requirements before launch. The app serves both the participant page and the organizer dashboard from one process, so participants get one public URL.

### Important database note

The included SQLite database is a real database and is excellent for local demos and a single persistent server. On hosts with ephemeral filesystems, SQLite data can disappear during redeploy/restart. For a real symposium with many registrations, use a managed PostgreSQL database (for example Supabase, Neon or Railway Postgres) or attach persistent storage to the host.

Before public deployment:

1. Set a strong `ADMIN_KEY` environment variable.
2. Set a persistent `DB_PATH` if your host provides a persistent disk, **or migrate the DB layer to PostgreSQL**.
3. Put the site behind HTTPS (most managed Node hosts provide this automatically).
4. Restrict `/admin` access to organizers and never publish the organizer key.
5. Test a registration from a phone and verify it appears in Mission Control and CSV export.
6. Decide whether your organizers want to allow 1–4 participants or enforce a minimum team size. The current implementation follows the registration brief and permits up to 4 total members.

## One-URL architecture

```text
Participant QR / URL
        ↓
Kraven's Gate Heist landing page
        ↓
POST /api/register
        ↓
Central database (SQLite locally / PostgreSQL or persistent SQLite in production)
        ↓
/admin → Mission Control
        ↓
Stats + full team list + CSV export
```

## PostgreSQL production migration

The UI and API contract are already separated from the database layer. To use Supabase/Neon/Railway Postgres, replace the SQLite statements in `server/index.js` with parameterized PostgreSQL queries and add a `DATABASE_URL` environment variable. Keep the same `/api/register`, `/api/admin/*` routes so the participant experience does not change.

For a staff demo, the included SQLite setup is enough. For actual public registration, a managed PostgreSQL database is recommended.

## Proposal alignment note

The uploaded proposal describes the event as a browser/zero-hardware technical heist and uses the dark cinematic red/pink, orange, cyan and gold visual language used here. The proposal text also lists a 2–3 detective squad size, while the registration specification in the build request explicitly asks for up to 4 members total. This website follows the build request's **up to 4 members** requirement; confirm the final team-size rule with organizers before launch.

import { createServer } from 'node:http';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const PUBLIC = path.join(ROOT, 'public');

const PORT = Number(process.env.PORT || 3000);

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;
const ADMIN_KEY = process.env.ADMIN_KEY;

if (!SUPABASE_URL) {
  throw new Error('SUPABASE_URL environment variable is missing.');
}

if (!SUPABASE_SECRET_KEY) {
  throw new Error('SUPABASE_SECRET_KEY environment variable is missing.');
}

if (!ADMIN_KEY) {
  throw new Error('ADMIN_KEY environment variable is missing.');
}

const SUPABASE_TABLE_URL = `${SUPABASE_URL}/rest/v1/teams`;
const ORGANIZERS_URL = `${SUPABASE_URL}/rest/v1/organizers`;

function supabaseHeaders(extra = {}) {
  return {
    apikey: SUPABASE_SECRET_KEY,
    Authorization: `Bearer ${SUPABASE_SECRET_KEY}`,
    'Content-Type': 'application/json',
    ...extra
  };
}


/* =========================================================
   VALIDATION
========================================================= */

const programs = new Set([
  'B.E.',
  'B.Tech.',
  'B.Sc.',
  'BCA',
  'MCA',
  'MBA',
  'M.E.',
  'M.Tech.',
  'M.Sc.',
  'Other'
]);

const years = new Set([
  '1st Year',
  '2nd Year',
  '3rd Year',
  '4th Year',
  'Final Year',
  'Postgraduate — 1st Year',
  'Postgraduate — 2nd Year',
  'Other'
]);

const organizerRoles = new Set([
  'organizer',
  'sub_organizer'
]);


function clean(v, max = 200) {
  return String(v ?? '')
    .trim()
    .replace(/\s+/g, ' ')
    .slice(0, max);
}


function emailOk(v) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(v);
}


function phoneOk(v) {
  return /^[0-9+()\-\s]{7,20}$/.test(v);
}


/* =========================================================
   PASSWORD HASHING
========================================================= */

function hashPassword(password) {

  const salt = crypto.randomBytes(16).toString('hex');

  const hash = crypto.scryptSync(
    password,
    salt,
    64
  ).toString('hex');

  return `${salt}:${hash}`;
}


function verifyPassword(password, stored) {

  try {

    const [salt, storedHash] = String(stored).split(':');

    if (!salt || !storedHash) {
      return false;
    }

    const hash = crypto.scryptSync(
      password,
      salt,
      64
    ).toString('hex');

    return crypto.timingSafeEqual(
      Buffer.from(hash, 'hex'),
      Buffer.from(storedHash, 'hex')
    );

  } catch {

    return false;
  }
}


/* =========================================================
   ORGANIZER SESSION
========================================================= */

function organizerToken(email) {

  return crypto
    .createHmac('sha256', ADMIN_KEY)
    .update(`organizer:${email}`)
    .digest('hex');
}


function parseCookies(req) {

  return Object.fromEntries(
    (req.headers.cookie || '')
      .split(';')
      .filter(Boolean)
      .map(x => {

        const i = x.indexOf('=');

        return [
          decodeURIComponent(x.slice(0, i).trim()),
          decodeURIComponent(x.slice(i + 1).trim())
        ];

      })
  );
}


/* =========================================================
   SUPABASE ORGANIZER LOOKUP
========================================================= */

async function getOrganizer(email) {

  const url =
    `${ORGANIZERS_URL}?select=*&email=eq.${encodeURIComponent(email)}&limit=1`;

  const response = await fetch(
    url,
    {
      headers: supabaseHeaders()
    }
  );

  if (!response.ok) {

    console.error(
      'Organizer lookup error:',
      await response.text()
    );

    throw new Error('Could not check organizer account.');
  }

  const rows = await response.json();

  return rows[0] || null;
}


/* =========================================================
   ORGANIZER AUTHORIZATION
========================================================= */

async function authorizedOrganizer(req) {

  const cookies = parseCookies(req);

  const email = cookies.kgh_organizer_email;
  const token = cookies.kgh_organizer;

  if (!email || !token) {
    return null;
  }

  if (token !== organizerToken(email)) {
    return null;
  }

  const organizer = await getOrganizer(email);

  if (!organizer) {
    return null;
  }

  if (organizer.approval_status !== 'approved') {
    return null;
  }

  return organizer;
}


/* =========================================================
   REQUEST BODY
========================================================= */

async function body(req) {

  let data = '';

  for await (const chunk of req) {
    data += chunk;
  }

  if (data.length > 60000) {
    throw new Error('Payload too large');
  }

  return JSON.parse(data || '{}');
}


/* =========================================================
   RESPONSE
========================================================= */

function json(res, status, obj, extra = {}) {

  const body = JSON.stringify(obj);

  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extra
  });

  res.end(body);
}


/* =========================================================
   STATIC FILES
========================================================= */

function contentType(file) {

  return {
    '.html': 'text/html; charset=utf-8',
    '.css': 'text/css; charset=utf-8',
    '.js': 'text/javascript; charset=utf-8',
    '.svg': 'image/svg+xml',
    '.png': 'image/png',
    '.jpg': 'image/jpeg',
    '.jpeg': 'image/jpeg',
    '.webp': 'image/webp'
  }[path.extname(file)] ||
  'application/octet-stream';
}


function serve(res, file) {

  try {

    const abs = path.resolve(PUBLIC, file);

    if (!abs.startsWith(PUBLIC)) {
      return res.writeHead(403).end();
    }

    const data = fs.readFileSync(abs);

    res.writeHead(200, {
      'Content-Type': contentType(abs),
      'Cache-Control': 'no-cache'
    });

    res.end(data);

  } catch {

    res.writeHead(404).end('Not found');

  }
}


/* =========================================================
   TEAM ID
========================================================= */

function randomTeamId() {

  return `KGH-${crypto
    .randomInt(0, 10000)
    .toString()
    .padStart(4, '0')}`;
}


/* =========================================================
   CREATE TEAM
========================================================= */

async function createTeam(payload) {

  const vals = {

    team_name: clean(payload.teamName, 80),

    college: clean(payload.college, 160),

    program: clean(payload.program, 40),

    department: clean(payload.department, 100),

    year_level: clean(payload.yearLevel, 80),

    leader_name: clean(payload.leaderName, 100),

    leader_reg_no: clean(payload.leaderRegNo, 60),

    leader_email:
      clean(payload.leaderEmail, 160).toLowerCase(),

    leader_phone:
      clean(payload.leaderPhone, 25)
  };


  if (!Object.values(vals).every(Boolean)) {

    throw {
      status: 400,
      message: 'Please complete all required fields.'
    };

  }


  if (!programs.has(vals.program)) {

    throw {
      status: 400,
      message: 'Please choose a valid program.'
    };

  }


  if (!years.has(vals.year_level)) {

    throw {
      status: 400,
      message: 'Please choose a valid academic level.'
    };

  }


  if (!emailOk(vals.leader_email)) {

    throw {
      status: 400,
      message: 'Please enter a valid email address.'
    };

  }


  if (!phoneOk(vals.leader_phone)) {

    throw {
      status: 400,
      message: 'Please enter a valid mobile number.'
    };

  }


  if (!(payload.consent === true ||
        payload.consent === 'true')) {

    throw {
      status: 400,
      message: 'Please confirm the declaration before submitting.'
    };

  }


  const members = [2, 3, 4].map(n => ({

    name: clean(payload[`member${n}Name`], 100),

    reg: clean(payload[`member${n}RegNo`], 60)

  }));


  for (let i = 0; i < members.length; i++) {

    const member = members[i];

    if (
      (member.name && !member.reg) ||
      (!member.name && member.reg)
    ) {

      throw {
        status: 400,
        message:
          `Member ${i + 2}: provide both name and College ID / Register Number, or leave both blank.`
      };

    }

  }


  for (let attempt = 0; attempt < 10; attempt++) {

    const teamId = randomTeamId();

    const row = {

      team_id: teamId,

      team_name: vals.team_name,

      college: vals.college,

      program: vals.program,

      department: vals.department,

      year_level: vals.year_level,

      leader_name: vals.leader_name,

      leader_reg_no: vals.leader_reg_no,

      leader_email: vals.leader_email,

      leader_phone: vals.leader_phone,

      member2_name: members[0].name || null,

      member2_reg_no: members[0].reg || null,

      member3_name: members[1].name || null,

      member3_reg_no: members[1].reg || null,

      member4_name: members[2].name || null,

      member4_reg_no: members[2].reg || null,

      consent: true,

      created_at: new Date().toISOString()
    };


    const response = await fetch(
      SUPABASE_TABLE_URL,
      {
        method: 'POST',

        headers: supabaseHeaders({
          Prefer: 'return=representation'
        }),

        body: JSON.stringify(row)
      }
    );


    if (response.ok) {

      const created = await response.json();

      return {

        teamId:
          created[0]?.team_id || teamId,

        createdAt:
          created[0]?.created_at || row.created_at

      };

    }


    const errorText = await response.text();

    if (
      response.status === 409 ||
      errorText.toLowerCase().includes('duplicate')
    ) {

      continue;

    }


    console.error(
      'Supabase registration error:',
      errorText
    );


    throw {
      status: 500,
      message:
        'Registration could not be saved. Please try again.'
    };

  }


  throw {
    status: 500,
    message:
      'Unable to generate a unique Team ID. Please try again.'
  };
}


/* =========================================================
   ORGANIZER REQUEST
========================================================= */

async function requestOrganizer(payload) {

  const name = clean(payload.name, 100);

  const email =
    clean(payload.email, 160).toLowerCase();

  const password =
    String(payload.password || '');

  const requestedRole =
    clean(payload.requestedRole, 40);


  if (!name || !email || !password) {

    throw {
      status: 400,
      message:
        'Please provide your name, email and password.'
    };

  }


  if (!emailOk(email)) {

    throw {
      status: 400,
      message:
        'Please enter a valid email address.'
    };

  }


  if (password.length < 8) {

    throw {
      status: 400,
      message:
        'Password must contain at least 8 characters.'
    };

  }


  if (!organizerRoles.has(requestedRole)) {

    throw {
      status: 400,
      message:
        'Please choose Organizer or Sub Organizer.'
    };

  }


  const existing = await getOrganizer(email);

  const passwordHash = hashPassword(password);


  if (existing) {

    if (
      existing.approval_status === 'approved'
    ) {

      throw {
        status: 409,
        message:
          'This email is already an approved organizer.'
      };

    }


    const response = await fetch(
      `${ORGANIZERS_URL}?email=eq.${encodeURIComponent(email)}`,
      {
        method: 'PATCH',

        headers: supabaseHeaders({
          Prefer: 'return=representation'
        }),

        body: JSON.stringify({

          name,

          password_hash: passwordHash,

          requested_role: requestedRole,

          role: requestedRole,

          approval_status: 'pending',

          approved_by: null,

          approved_at: null

        })

      }
    );


    if (!response.ok) {

      console.error(
        'Organizer update error:',
        await response.text()
      );

      throw new Error(
        'Could not submit organizer request.'
      );

    }

  } else {

    const response = await fetch(
      ORGANIZERS_URL,
      {
        method: 'POST',

        headers: supabaseHeaders({
          Prefer: 'return=representation'
        }),

        body: JSON.stringify({

          name,

          email,

          role: requestedRole,

          requested_role: requestedRole,

          password_hash: passwordHash,

          approval_status: 'pending'

        })

      }
    );


    if (!response.ok) {

      console.error(
        'Organizer request error:',
        await response.text()
      );

      throw new Error(
        'Could not submit organizer request.'
      );

    }

  }


  return {
    ok: true,
    message:
      'Organizer request submitted. Please wait for Organizer Head approval.'
  };
}


/* =========================================================
   ORGANIZER LOGIN
========================================================= */

async function organizerLogin(payload) {

  const email =
    clean(payload.email, 160).toLowerCase();

  const password =
    String(payload.password || '');


  if (!email || !password) {

    throw {
      status: 400,
      message:
        'Please enter your organizer email and password.'
    };

  }


  const organizer =
    await getOrganizer(email);


  if (!organizer) {

    throw {
      status: 401,
      message:
        'No organizer account was found for this email.'
    };

  }


  if (
    organizer.approval_status !== 'approved'
  ) {

    throw {
      status: 403,
      message:
        'Your organizer access has not been approved yet.'
    };

  }


  if (
    !organizer.password_hash ||
    !verifyPassword(
      password,
      organizer.password_hash
    )
  ) {

    throw {
      status: 401,
      message:
        'Incorrect organizer email or password.'
    };

  }


  const token =
    organizerToken(email);


  return {
    organizer,
    token
  };
}


/* =========================================================
   GET TEAMS
========================================================= */

async function getTeams() {

  const response = await fetch(
    `${SUPABASE_TABLE_URL}?select=*&order=id.desc`,
    {
      headers: supabaseHeaders()
    }
  );


  if (!response.ok) {

    console.error(
      'Supabase teams error:',
      await response.text()
    );

    throw new Error(
      'Could not load registered teams.'
    );

  }


  return await response.json();
}


/* =========================================================
   SERVER
========================================================= */

const server =
  createServer(async (req, res) => {

    try {

      const url =
        new URL(
          req.url,
          `http://${req.headers.host || 'localhost'}`
        );

      const p = url.pathname;


      /* ===============================================
         STUDENT REGISTRATION
      =============================================== */

      if (
        req.method === 'POST' &&
        p === '/api/register'
      ) {

        const b = await body(req);

        const result =
          await createTeam(b);

        return json(
          res,
          201,
          result
        );

      }


      /* ===============================================
         ORGANIZER REQUEST
      =============================================== */

      if (
        req.method === 'POST' &&
        p === '/api/organizer/request'
      ) {

        const b = await body(req);

        const result =
          await requestOrganizer(b);

        return json(
          res,
          201,
          result
        );

      }


      /* ===============================================
         ORGANIZER LOGIN
      =============================================== */

      if (
        req.method === 'POST' &&
        p === '/api/organizer/login'
      ) {

        const b = await body(req);

        const result =
          await organizerLogin(b);


        return json(
          res,
          200,
          {
            ok: true,

            organizer: {
              name: result.organizer.name,

              email: result.organizer.email,

              role: result.organizer.role
            }

          },
          {
            'Set-Cookie': [
              `kgh_organizer_email=${encodeURIComponent(
                result.organizer.email
              )}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`,

              `kgh_organizer=${result.token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`
            ]
          }
        );

      }


      /* ===============================================
         ORGANIZER SESSION CHECK
      =============================================== */

      if (
        req.method === 'GET' &&
        p === '/api/organizer/me'
      ) {

        const organizer =
          await authorizedOrganizer(req);


        if (!organizer) {

          return json(
            res,
            401,
            {
              error:
                'Organizer authentication required.'
            }
          );

        }


        return json(
          res,
          200,
          {
            ok: true,

            organizer: {
              name: organizer.name,

              email: organizer.email,

              role: organizer.role
            }
          }
        );

      }


      /* ===============================================
         PROTECTED ORGANIZER API
      =============================================== */

      if (
        p.startsWith('/api/admin/')
      ) {

        const organizer =
          await authorizedOrganizer(req);


        if (!organizer) {

          return json(
            res,
            401,
            {
              error:
                'Unauthorized organizer access.'
            }
          );

        }


        /* ---------------------------------------------
           STATS
        --------------------------------------------- */

        if (
          req.method === 'GET' &&
          p === '/api/admin/stats'
        ) {

          const teams =
            await getTeams();


          const todayString =
            new Date()
              .toISOString()
              .slice(0, 10);


          const today =
            teams.filter(
              team =>
                String(team.created_at)
                  .slice(0, 10) ===
                todayString
            ).length;


          const colleges =
            new Set(
              teams.map(team => team.college)
            ).size;


          return json(
            res,
            200,
            {
              total: teams.length,

              colleges,

              today
            }
          );

        }


        /* ---------------------------------------------
           TEAM LIST
        --------------------------------------------- */

        if (
          req.method === 'GET' &&
          p === '/api/admin/teams'
        ) {

          const teams =
            await getTeams();

          return json(
            res,
            200,
            teams
          );

        }


        /* ---------------------------------------------
           ORGANIZER LIST
        --------------------------------------------- */

        if (
          req.method === 'GET' &&
          p === '/api/admin/organizers'
        ) {

          const response =
            await fetch(
              `${ORGANIZERS_URL}?select=id,name,email,role,requested_role,approval_status,approved_by,approved_at,created_at&order=id.desc`,
              {
                headers:
                  supabaseHeaders()
              }
            );


          if (!response.ok) {

            throw new Error(
              'Could not load organizers.'
            );

          }


          const organizers =
            await response.json();


          return json(
            res,
            200,
            organizers
          );

        }


        /* ---------------------------------------------
           CSV
        --------------------------------------------- */

        if (
          req.method === 'GET' &&
          p === '/api/admin/export.csv'
        ) {

          const rows =
            await getTeams();


          const headers = [
            'Team ID',
            'Team Name',
            'College',
            'Program',
            'Department',
            'Year',
            'Leader Name',
            'Leader Register No',
            'Leader Email',
            'Leader Phone',
            'Member 2 Name',
            'Member 2 Register No',
            'Member 3 Name',
            'Member 3 Register No',
            'Member 4 Name',
            'Member 4 Register No',
            'Registration Time'
          ];


          const keys = [
            'team_id',
            'team_name',
            'college',
            'program',
            'department',
            'year_level',
            'leader_name',
            'leader_reg_no',
            'leader_email',
            'leader_phone',
            'member2_name',
            'member2_reg_no',
            'member3_name',
            'member3_reg_no',
            'member4_name',
            'member4_reg_no',
            'created_at'
          ];


          const esc =
            value =>
              `"${String(value ?? '')
                .replaceAll('"', '""')}"`;


          const csv = [

            headers
              .map(esc)
              .join(','),

            ...rows.map(
              row =>
                keys
                  .map(key => esc(row[key]))
                  .join(',')
            )

          ].join('\n');


          res.writeHead(
            200,
            {
              'Content-Type':
                'text/csv; charset=utf-8',

              'Content-Disposition':
                'attachment; filename="kravens-gate-heist-registrations.csv"'
            }
          );


          return res.end(csv);

        }

      }


      /* ===============================================
         STATIC PAGES
      =============================================== */

      if (req.method === 'GET') {

        if (p === '/admin') {

          return serve(
            res,
            'admin.html'
          );

        }


        const safe =
          p === '/'
            ? 'index.html'
            : p.slice(1);


        return serve(
          res,
          safe
        );

      }


      res
        .writeHead(404)
        .end('Not found');


    } catch (error) {

      console.error(error);


      if (error?.status) {

        return json(
          res,
          error.status,
          {
            error:
              error.message
          }
        );

      }


      return json(
        res,
        500,
        {
          error:
            'Server error. Please try again.'
        }
      );

    }

  });


server.listen(
  PORT,
  () =>
    console.log(
      `KGH registration running on port ${PORT}`
    )
);
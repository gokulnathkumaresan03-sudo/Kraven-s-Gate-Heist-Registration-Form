import { createServer } from 'node:http';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

/* =========================================================
   BASIC CONFIGURATION
========================================================= */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROOT = path.resolve(__dirname, '..');
const PUBLIC = path.join(ROOT, 'public');
const PORT = Number(process.env.PORT || 3000);

/* =========================================================
   ENVIRONMENT VARIABLES
========================================================= */

const SUPABASE_URL = process.env.SUPABASE_URL;
const SUPABASE_SECRET_KEY = process.env.SUPABASE_SECRET_KEY;
const ADMIN_KEY = process.env.ADMIN_KEY;

const MAIN_ORGANIZER_EMAIL = (
  process.env.MAIN_ORGANIZER_EMAIL ||
  'gokulnathkumaresan03@gmail.com'
)
  .trim()
  .toLowerCase();

/* =========================================================
   ENVIRONMENT CHECK
========================================================= */

if (!SUPABASE_URL) {
  throw new Error(
    'SUPABASE_URL environment variable is missing.'
  );
}

if (!SUPABASE_SECRET_KEY) {
  throw new Error(
    'SUPABASE_SECRET_KEY environment variable is missing.'
  );
}

if (!ADMIN_KEY) {
  throw new Error(
    'ADMIN_KEY environment variable is missing.'
  );
}

/* =========================================================
   SUPABASE URLS
========================================================= */

const TEAMS_URL = `${SUPABASE_URL}/rest/v1/teams`;
const ORGANIZERS_URL = `${SUPABASE_URL}/rest/v1/organizers`;

/* =========================================================
   SUPABASE HEADERS
========================================================= */

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

/* =========================================================
   CLEAN INPUT
========================================================= */

function clean(value, max = 200) {
  return String(value ?? '')
    .trim()
    .replace(/\s+/g, ' ')
    .slice(0, max);
}

/* =========================================================
   EMAIL VALIDATION
========================================================= */

function emailOk(value) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(value);
}

/* =========================================================
   PHONE VALIDATION
========================================================= */

function phoneOk(value) {
  return /^[0-9+()\-\s]{7,20}$/.test(value);
}

/* =========================================================
   PASSWORD HASH
========================================================= */

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');

  const hash = crypto
    .scryptSync(password, salt, 64)
    .toString('hex');

  return `${salt}:${hash}`;
}

/* =========================================================
   PASSWORD VERIFY
========================================================= */

function verifyPassword(password, stored) {
  try {
    const parts = String(stored).split(':');

    const salt = parts[0];
    const storedHash = parts[1];

    if (!salt || !storedHash) {
      return false;
    }

    const hash = crypto
      .scryptSync(password, salt, 64)
      .toString('hex');

    const actual = Buffer.from(hash, 'hex');
    const expected = Buffer.from(storedHash, 'hex');

    if (actual.length !== expected.length) {
      return false;
    }

    return crypto.timingSafeEqual(
      actual,
      expected
    );
  } catch {
    return false;
  }
}

/* =========================================================
   ORGANIZER TOKEN
========================================================= */

function organizerToken(email) {
  return crypto
    .createHmac('sha256', ADMIN_KEY)
    .update(`organizer:${email}`)
    .digest('hex');
}

/* =========================================================
   STUDENT EVENT TOKEN
========================================================= */

function eventToken(teamId) {
  return crypto
    .createHmac('sha256', ADMIN_KEY)
    .update(`event:${teamId}`)
    .digest('hex');
}

/* =========================================================
   ADMIN TOKEN
========================================================= */

function adminToken() {
  return crypto
    .createHmac('sha256', ADMIN_KEY)
    .update('admin')
    .digest('hex');
}

/* =========================================================
   COOKIE PARSER
========================================================= */

function parseCookies(req) {
  return Object.fromEntries(
    (req.headers.cookie || '')
      .split(';')
      .filter(Boolean)
      .map(cookie => {
        const index = cookie.indexOf('=');

        if (index === -1) {
          return ['', ''];
        }

        return [
          decodeURIComponent(
            cookie.slice(0, index).trim()
          ),
          decodeURIComponent(
            cookie.slice(index + 1).trim()
          )
        ];
      })
  );
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
    throw {
      status: 413,
      message: 'Payload too large.'
    };
  }

  try {
    return JSON.parse(data || '{}');
  } catch {
    throw {
      status: 400,
      message: 'Invalid JSON request.'
    };
  }
}

/* =========================================================
   JSON RESPONSE
========================================================= */

function json(res, status, obj, extra = {}) {
  const responseBody = JSON.stringify(obj);

  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Cache-Control': 'no-store',
    ...extra
  });

  res.end(responseBody);
}

/* =========================================================
   CONTENT TYPE
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
    '.webp': 'image/webp',
    '.ico': 'image/x-icon'
  }[
    path.extname(file).toLowerCase()
  ] || 'application/octet-stream';
}

/* =========================================================
   STATIC FILE SERVER
========================================================= */

function serve(res, file) {
  try {
    const abs = path.resolve(PUBLIC, file);

    if (
      abs !== PUBLIC &&
      !abs.startsWith(PUBLIC + path.sep)
    ) {
      return res
        .writeHead(403)
        .end('Forbidden');
    }

    const data = fs.readFileSync(abs);

    res.writeHead(200, {
      'Content-Type': contentType(abs),
      'Cache-Control': 'no-cache'
    });

    res.end(data);
  } catch {
    res
      .writeHead(404)
      .end('Not found');
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
   GET ORGANIZER
========================================================= */

async function getOrganizer(email) {
  const url =
    `${ORGANIZERS_URL}` +
    `?select=*` +
    `&email=eq.${encodeURIComponent(email)}` +
    `&limit=1`;

  const response = await fetch(url, {
    headers: supabaseHeaders()
  });

  if (!response.ok) {
    console.error(
      'Organizer lookup:',
      await response.text()
    );

    throw new Error(
      'Could not check organizer account.'
    );
  }

  const rows = await response.json();

  return rows[0] || null;
}

/* =========================================================
   GET TEAM BY TEAM ID + LEADER EMAIL
========================================================= */

async function getEventTeam(teamId, email) {
  const safeTeamId = clean(teamId, 30).toUpperCase();
  const safeEmail = clean(email, 160).toLowerCase();

  if (!safeTeamId || !safeEmail) {
    return null;
  }

  const url =
    `${TEAMS_URL}` +
    `?select=*` +
    `&team_id=eq.${encodeURIComponent(safeTeamId)}` +
    `&leader_email=eq.${encodeURIComponent(safeEmail)}` +
    `&limit=1`;

  const response = await fetch(url, {
    headers: supabaseHeaders()
  });

  if (!response.ok) {
    console.error(
      'Event team lookup:',
      await response.text()
    );

    throw new Error(
      'Could not verify event team.'
    );
  }

  const rows = await response.json();

  return rows[0] || null;
}

/* =========================================================
   GET TEAM BY ID
========================================================= */

async function getTeamById(teamId) {
  const safeTeamId = clean(teamId, 30).toUpperCase();

  if (!safeTeamId) {
    return null;
  }

  const url =
    `${TEAMS_URL}` +
    `?select=*` +
    `&team_id=eq.${encodeURIComponent(safeTeamId)}` +
    `&limit=1`;

  const response = await fetch(url, {
    headers: supabaseHeaders()
  });

  if (!response.ok) {
    console.error(
      'Team lookup:',
      await response.text()
    );

    throw new Error(
      'Could not check team.'
    );
  }

  const rows = await response.json();

  return rows[0] || null;
}

/* =========================================================
   AUTHORIZED EVENT TEAM
========================================================= */

async function authorizedEventTeam(req) {
  const cookies = parseCookies(req);

  const teamId = cookies.kgh_event_team;
  const token = cookies.kgh_event_token;

  if (!teamId || !token) {
    return null;
  }

  const expected = eventToken(teamId);

  if (token !== expected) {
    return null;
  }

  const team = await getTeamById(teamId);

  if (!team) {
    return null;
  }

  return team;
}

/* =========================================================
   EVENT LOGIN
========================================================= */

async function eventLogin(payload) {
  const teamId = clean(
    payload.teamId,
    30
  ).toUpperCase();

  const email = clean(
    payload.email,
    160
  ).toLowerCase();

  if (!teamId || !email) {
    throw {
      status: 400,
      message:
        'Please enter your Team ID and registered leader email.'
    };
  }

  if (!emailOk(email)) {
    throw {
      status: 400,
      message:
        'Please enter a valid registered email address.'
    };
  }

  const team = await getEventTeam(
    teamId,
    email
  );

  if (!team) {
    throw {
      status: 401,
      message:
        'Team ID and registered email do not match any registered team.'
    };
  }

  return {
    team: {
      team_id: team.team_id,
      team_name: team.team_name,
      college: team.college,
      program: team.program,
      department: team.department,
      year_level: team.year_level,
      leader_name: team.leader_name
    },

    token: eventToken(team.team_id)
  };
}

/* =========================================================
   AUTHORIZED ORGANIZER
========================================================= */

async function authorizedOrganizer(req) {
  const cookies = parseCookies(req);

  const email = cookies.kgh_organizer_email;
  const token = cookies.kgh_organizer;

  if (!email || !token) {
    return null;
  }

  const expected = organizerToken(email);

  if (token !== expected) {
    return null;
  }

  const organizer = await getOrganizer(email);

  if (!organizer) {
    return null;
  }

  if (
    organizer.approval_status !==
    'approved'
  ) {
    return null;
  }

  return organizer;
}

/* =========================================================
   AUTHORIZED ADMIN
========================================================= */

function authorizedAdmin(req) {
  const cookies = parseCookies(req);

  return (
    cookies.kgh_admin === adminToken() ||
    req.headers['x-admin-key'] === ADMIN_KEY
  );
}

/* =========================================================
   ORGANIZER HEAD CHECK
========================================================= */

function isOrganizerHead(organizer) {
  if (!organizer) {
    return false;
  }

  const email = String(
    organizer.email || ''
  )
    .trim()
    .toLowerCase();

  return (
    email === MAIN_ORGANIZER_EMAIL ||
    organizer.role === 'organizer_head'
  );
}

/* =========================================================
   CREATE TEAM
========================================================= */

async function createTeam(payload) {
  const vals = {
    team_name: clean(
      payload.teamName,
      80
    ),

    college: clean(
      payload.college,
      160
    ),

    program: clean(
      payload.program,
      40
    ),

    department: clean(
      payload.department,
      100
    ),

    year_level: clean(
      payload.yearLevel,
      80
    ),

    leader_name: clean(
      payload.leaderName,
      100
    ),

    leader_reg_no: clean(
      payload.leaderRegNo,
      60
    ),

    leader_email: clean(
      payload.leaderEmail,
      160
    ).toLowerCase(),

    leader_phone: clean(
      payload.leaderPhone,
      25
    )
  };

  if (
    !Object.values(vals).every(Boolean)
  ) {
    throw {
      status: 400,
      message:
        'Please complete all required fields.'
    };
  }

  if (!programs.has(vals.program)) {
    throw {
      status: 400,
      message:
        'Please choose a valid program.'
    };
  }

  if (!years.has(vals.year_level)) {
    throw {
      status: 400,
      message:
        'Please choose a valid academic level.'
    };
  }

  if (!emailOk(vals.leader_email)) {
    throw {
      status: 400,
      message:
        'Please enter a valid email address.'
    };
  }

  if (!phoneOk(vals.leader_phone)) {
    throw {
      status: 400,
      message:
        'Please enter a valid mobile number.'
    };
  }

  if (
    !(
      payload.consent === true ||
      payload.consent === 'true'
    )
  ) {
    throw {
      status: 400,
      message:
        'Please confirm the declaration before submitting.'
    };
  }

  const members = [2, 3, 4].map(
    number => ({
      name: clean(
        payload[`member${number}Name`],
        100
      ),

      reg: clean(
        payload[`member${number}RegNo`],
        60
      )
    })
  );

  for (
    let i = 0;
    i < members.length;
    i++
  ) {
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

  for (
    let attempt = 0;
    attempt < 10;
    attempt++
  ) {
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

      member2_name:
        members[0].name || null,

      member2_reg_no:
        members[0].reg || null,

      member3_name:
        members[1].name || null,

      member3_reg_no:
        members[1].reg || null,

      member4_name:
        members[2].name || null,

      member4_reg_no:
        members[2].reg || null,

      consent: true,

      created_at:
        new Date().toISOString()
    };

    const response = await fetch(
      TEAMS_URL,
      {
        method: 'POST',

        headers: supabaseHeaders({
          Prefer:
            'return=representation'
        }),

        body: JSON.stringify(row)
      }
    );

    if (response.ok) {
      const created =
        await response.json();

      return {
        teamId:
          created[0]?.team_id ||
          teamId,

        createdAt:
          created[0]?.created_at ||
          row.created_at
      };
    }

    const errorText =
      await response.text();

    if (
      response.status === 409 ||
      errorText
        .toLowerCase()
        .includes('duplicate')
    ) {
      continue;
    }

    console.error(
      'Registration error:',
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
      'Unable to generate a unique Team ID.'
  };
}

/* =========================================================
   ORGANIZER REQUEST
========================================================= */

async function requestOrganizer(payload) {
  const name = clean(
    payload.name,
    100
  );

  const email = clean(
    payload.email,
    160
  ).toLowerCase();

  const password = String(
    payload.password || ''
  );

  const requestedRole = clean(
    payload.requestedRole,
    40
  );

  if (
    !name ||
    !email ||
    !password
  ) {
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

  if (
    !organizerRoles.has(
      requestedRole
    )
  ) {
    throw {
      status: 400,
      message:
        'Please choose Organizer or Sub Organizer.'
    };
  }

  if (
    email === MAIN_ORGANIZER_EMAIL
  ) {
    throw {
      status: 400,
      message:
        'The Organizer Head account is managed by the event administration.'
    };
  }

  const existing =
    await getOrganizer(email);

  const passwordHash =
    hashPassword(password);

  if (existing) {
    if (
      existing.approval_status ===
      'approved'
    ) {
      throw {
        status: 409,
        message:
          'This email already has approved organizer access.'
      };
    }

    const response = await fetch(
      `${ORGANIZERS_URL}?email=eq.${encodeURIComponent(email)}`,
      {
        method: 'PATCH',

        headers: supabaseHeaders({
          Prefer:
            'return=representation'
        }),

        body: JSON.stringify({
          name,

          password_hash:
            passwordHash,

          requested_role:
            requestedRole,

          role:
            requestedRole,

          approval_status:
            'pending',

          approved_by: null,

          approved_at: null
        })
      }
    );

    if (!response.ok) {
      console.error(
        'Organizer update:',
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
          Prefer:
            'return=representation'
        }),

        body: JSON.stringify({
          name,

          email,

          role:
            requestedRole,

          requested_role:
            requestedRole,

          password_hash:
            passwordHash,

          approval_status:
            'pending',

          approved_by: null,

          approved_at: null
        })
      }
    );

    if (!response.ok) {
      console.error(
        'Organizer request:',
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
      'Organizer request submitted successfully. Please wait for Organizer Head approval.'
  };
}

/* =========================================================
   ORGANIZER LOGIN
========================================================= */

async function organizerLogin(payload) {
  const email = clean(
    payload.email,
    160
  ).toLowerCase();

  const password = String(
    payload.password || ''
  );

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

  if (!organizer.password_hash) {
    throw {
      status: 401,
      message:
        'This organizer account does not have a valid password.'
    };
  }

  if (
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

  const head =
    isOrganizerHead(organizer);

  if (
    !head &&
    organizer.approval_status !==
      'approved'
  ) {
    throw {
      status: 403,
      message:
        'Your organizer access has not been approved yet.'
    };
  }

  return {
    organizer,

    token:
      organizerToken(email)
  };
}

/* =========================================================
   GET TEAMS
========================================================= */

async function getTeams() {
  const response = await fetch(
    `${TEAMS_URL}?select=*&order=id.desc`,
    {
      headers:
        supabaseHeaders()
    }
  );

  if (!response.ok) {
    console.error(
      'Teams error:',
      await response.text()
    );

    throw new Error(
      'Could not load registered teams.'
    );
  }

  return await response.json();
}

/* =========================================================
   GET ORGANIZERS
========================================================= */

async function getOrganizers() {
  const url =
    `${ORGANIZERS_URL}` +
    `?select=id,name,email,role,requested_role,approval_status,approved_by,approved_at,created_at` +
    `&order=id.desc`;

  const response = await fetch(
    url,
    {
      headers:
        supabaseHeaders()
    }
  );

  if (!response.ok) {
    console.error(
      'Organizer list:',
      await response.text()
    );

    throw new Error(
      'Could not load organizers.'
    );
  }

  return await response.json();
}

/* =========================================================
   UPDATE ORGANIZER
========================================================= */

async function updateOrganizer(
  id,
  action,
  approver
) {
  if (
    action !== 'approve' &&
    action !== 'reject'
  ) {
    throw {
      status: 400,
      message:
        'Invalid organizer action.'
    };
  }

  const existingResponse =
    await fetch(
      `${ORGANIZERS_URL}?id=eq.${encodeURIComponent(id)}&select=*`,
      {
        headers:
          supabaseHeaders()
      }
    );

  if (!existingResponse.ok) {
    throw new Error(
      'Could not find organizer.'
    );
  }

  const rows =
    await existingResponse.json();

  const target = rows[0];

  if (!target) {
    throw {
      status: 404,
      message:
        'Organizer account not found.'
    };
  }

  if (
    String(target.email)
      .toLowerCase() ===
    MAIN_ORGANIZER_EMAIL
  ) {
    throw {
      status: 403,
      message:
        'The Organizer Head account cannot be modified here.'
    };
  }

  const now =
    new Date().toISOString();

  const approved =
    action === 'approve';

  const update = {
    approval_status:
      approved
        ? 'approved'
        : 'rejected',

    approved_by:
      approved
        ? approver.email
        : null,

    approved_at:
      approved
        ? now
        : null
  };

  const response =
    await fetch(
      `${ORGANIZERS_URL}?id=eq.${encodeURIComponent(id)}`,
      {
        method: 'PATCH',

        headers:
          supabaseHeaders({
            Prefer:
              'return=representation'
          }),

        body:
          JSON.stringify(update)
      }
    );

  if (!response.ok) {
    console.error(
      'Organizer approval:',
      await response.text()
    );

    throw new Error(
      `Could not ${action} organizer.`
    );
  }

  return {
    ok: true,

    message:
      approved
        ? 'Organizer approved successfully.'
        : 'Organizer rejected successfully.'
  };
}

/* =========================================================
   SERVER
========================================================= */

const server = createServer(
  async (req, res) => {
    try {
      const url = new URL(
        req.url,
        `http://${req.headers.host || 'localhost'}`
      );

      const p = url.pathname;

      /* =================================================
         STUDENT REGISTRATION
      ================================================= */

      if (
        req.method === 'POST' &&
        p === '/api/register'
      ) {
        const result =
          await createTeam(
            await body(req)
          );

        return json(
          res,
          201,
          result
        );
      }

      /* =================================================
         ORGANIZER REQUEST
      ================================================= */

      if (
        req.method === 'POST' &&
        p === '/api/organizer/request'
      ) {
        const result =
          await requestOrganizer(
            await body(req)
          );

        return json(
          res,
          201,
          result
        );
      }

      /* =================================================
         ORGANIZER LOGIN
      ================================================= */

      if (
        req.method === 'POST' &&
        p === '/api/organizer/login'
      ) {
        const result =
          await organizerLogin(
            await body(req)
          );

        const head =
          isOrganizerHead(
            result.organizer
          );

        return json(
          res,
          200,
          {
            ok: true,

            organizer: {
              name:
                result.organizer.name,

              email:
                result.organizer.email,

              role:
                head
                  ? 'organizer_head'
                  : (
                    result.organizer.role ||
                    'organizer'
                  )
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

      /* =================================================
         ORGANIZER SESSION
      ================================================= */

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

        const head =
          isOrganizerHead(
            organizer
          );

        return json(
          res,
          200,
          {
            ok: true,

            organizer: {
              name:
                organizer.name,

              email:
                organizer.email,

              role:
                head
                  ? 'organizer_head'
                  : (
                    organizer.role ||
                    'organizer'
                  )
            }
          }
        );
      }

      /* =================================================
         ORGANIZER LOGOUT
      ================================================= */

      if (
        req.method === 'POST' &&
        p === '/api/organizer/logout'
      ) {
        return json(
          res,
          200,
          {
            ok: true
          },
          {
            'Set-Cookie': [
              'kgh_organizer_email=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0',

              'kgh_organizer=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'
            ]
          }
        );
      }

      /* =================================================
         STUDENT EVENT LOGIN
      ================================================= */

      if (
        req.method === 'POST' &&
        p === '/api/event/login'
      ) {
        const result =
          await eventLogin(
            await body(req)
          );

        return json(
          res,
          200,
          {
            ok: true,
            team: result.team
          },
          {
            'Set-Cookie': [
              `kgh_event_team=${encodeURIComponent(
                result.team.team_id
              )}; HttpOnly; SameSite=Strict; Path=/; Max-Age=14400`,

              `kgh_event_token=${result.token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=14400`
            ]
          }
        );
      }

      /* =================================================
         STUDENT EVENT SESSION
      ================================================= */

      if (
        req.method === 'GET' &&
        p === '/api/event/me'
      ) {
        const team =
          await authorizedEventTeam(req);

        if (!team) {
          return json(
            res,
            401,
            {
              error:
                'Student event authentication required.'
            }
          );
        }

        return json(
          res,
          200,
          {
            ok: true,

            team: {
              team_id:
                team.team_id,

              team_name:
                team.team_name,

              college:
                team.college,

              program:
                team.program,

              department:
                team.department,

              year_level:
                team.year_level,

              leader_name:
                team.leader_name
            }
          }
        );
      }

      /* =================================================
         STUDENT EVENT LOGOUT
      ================================================= */

      if (
        req.method === 'POST' &&
        p === '/api/event/logout'
      ) {
        return json(
          res,
          200,
          {
            ok: true
          },
          {
            'Set-Cookie': [
              'kgh_event_team=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0',

              'kgh_event_token=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0'
            ]
          }
        );
      }

      /* =================================================
         ADMIN LOGIN — LEGACY / MASTER ACCESS
      ================================================= */

      if (
        req.method === 'POST' &&
        p === '/api/admin/login'
      ) {
        const b =
          await body(req);

        if (
          b.key !== ADMIN_KEY
        ) {
          return json(
            res,
            401,
            {
              error:
                'Invalid organizer key.'
            }
          );
        }

        return json(
          res,
          200,
          {
            ok: true
          },
          {
            'Set-Cookie':
              `kgh_admin=${adminToken()}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`
          }
        );
      }

      /* =================================================
         PROTECTED ADMIN API
      ================================================= */

      if (
        p.startsWith('/api/admin/')
      ) {
        const organizer =
          await authorizedOrganizer(req);

        const admin =
          authorizedAdmin(req);

        if (
          !organizer &&
          !admin
        ) {
          return json(
            res,
            401,
            {
              error:
                'Unauthorized organizer access.'
            }
          );
        }

        /* ===============================================
           APPROVE / REJECT ORGANIZER
        =============================================== */

        if (
          req.method === 'POST' &&
          /^\/api\/admin\/organizers\/[^/]+\/(approve|reject)$/.test(p)
        ) {
          if (
            !admin &&
            !isOrganizerHead(
              organizer
            )
          ) {
            return json(
              res,
              403,
              {
                error:
                  'Only the Organizer Head can approve or reject organizers.'
              }
            );
          }

          const match =
            p.match(
              /^\/api\/admin\/organizers\/([^/]+)\/(approve|reject)$/
            );

          const id =
            match[1];

          const action =
            match[2];

          const approver =
            organizer || {
              email:
                MAIN_ORGANIZER_EMAIL
            };

          const result =
            await updateOrganizer(
              id,
              action,
              approver
            );

          return json(
            res,
            200,
            result
          );
        }

        /* ===============================================
           STATS
        =============================================== */

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
                String(
                  team.created_at
                ).slice(0, 10) ===
                todayString
            ).length;

          const colleges =
            new Set(
              teams.map(
                team =>
                  team.college
              )
            ).size;

          return json(
            res,
            200,
            {
              total:
                teams.length,

              colleges,

              today
            }
          );
        }

        /* ===============================================
           TEAM LIST
        =============================================== */

        if (
          req.method === 'GET' &&
          p === '/api/admin/teams'
        ) {
          return json(
            res,
            200,
            await getTeams()
          );
        }

        /* ===============================================
           ORGANIZER LIST
        =============================================== */

        if (
          req.method === 'GET' &&
          p === '/api/admin/organizers'
        ) {
          return json(
            res,
            200,
            await getOrganizers()
          );
        }

        /* ===============================================
           CSV EXPORT
        =============================================== */

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

          const csvEsc =
            value =>
              `"${String(
                value ?? ''
              ).replaceAll(
                '"',
                '""'
              )}"`;

          const csv = [
            headers
              .map(csvEsc)
              .join(','),

            ...rows.map(
              row =>
                keys
                  .map(
                    key =>
                      csvEsc(
                        row[key]
                      )
                  )
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

      /* =================================================
         STATIC PAGES
      ================================================= */

      if (
        req.method === 'GET'
      ) {
        if (p === '/') {
          return serve(
            res,
            'index.html'
          );
        }

        if (p === '/admin') {
          return serve(
            res,
            'admin.html'
          );
        }

        if (p === '/organizer') {
          return serve(
            res,
            'organizer.html'
          );
        }

        if (
          p === '/organizer-request'
        ) {
          return serve(
            res,
            'organizer_request.html'
          );
        }

        if (p === '/event') {
          return serve(
            res,
            'event.html'
          );
        }

        if (p === '/round') {
          return serve(
            res,
            'round.html'
          );
        }

        if (p === '/result') {
          return serve(
            res,
            'result.html'
          );
        }

        if (p === '/final') {
          return serve(
            res,
            'final.html'
          );
        }

        if (p === '/projector') {
          return serve(
            res,
            'projector.html'
          );
        }

        const safe =
          p.startsWith('/')
            ? p.slice(1)
            : p;

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
  }
);

/* =========================================================
   START SERVER
========================================================= */

server.listen(
  PORT,
  () => {
    console.log(
      `KGH registration running on port ${PORT}`
    );
  }
);
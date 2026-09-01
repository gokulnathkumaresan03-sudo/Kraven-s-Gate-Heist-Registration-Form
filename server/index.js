```js
import { createServer } from 'node:http';
import crypto from 'node:crypto';
import path from 'node:path';
import fs from 'node:fs';
import { fileURLToPath } from 'node:url';

/* =========================================================
   BASIC CONFIGURATION
========================================================= */

const __dirname =
  path.dirname(
    fileURLToPath(import.meta.url)
  );

const ROOT =
  path.resolve(
    __dirname,
    '..'
  );

const PUBLIC =
  path.join(
    ROOT,
    'public'
  );

const PORT =
  Number(
    process.env.PORT || 3000
  );

/* =========================================================
   ENVIRONMENT VARIABLES
========================================================= */

const SUPABASE_URL =
  process.env.SUPABASE_URL;

const SUPABASE_SECRET_KEY =
  process.env.SUPABASE_SECRET_KEY;

const ADMIN_KEY =
  process.env.ADMIN_KEY;

const ORGANIZER_HEAD_PASSWORD =
  process.env.ORGANIZER_HEAD_PASSWORD;

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

if (!ORGANIZER_HEAD_PASSWORD) {
  throw new Error(
    'ORGANIZER_HEAD_PASSWORD environment variable is missing.'
  );
}

if (
  ORGANIZER_HEAD_PASSWORD.length < 8
) {
  throw new Error(
    'ORGANIZER_HEAD_PASSWORD must be at least 8 characters.'
  );
}

/* =========================================================
   SUPABASE URLS
========================================================= */

const TEAMS_URL =
  `${SUPABASE_URL}/rest/v1/teams`;

const ORGANIZERS_URL =
  `${SUPABASE_URL}/rest/v1/organizers`;

/* =========================================================
   SUPABASE HEADERS
========================================================= */

function supabaseHeaders(extra = {}) {
  return {
    apikey:
      SUPABASE_SECRET_KEY,

    Authorization:
      `Bearer ${SUPABASE_SECRET_KEY}`,

    'Content-Type':
      'application/json',

    ...extra
  };
}

/* =========================================================
   VALIDATION
========================================================= */

const programs =
  new Set([
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

const years =
  new Set([
    '1st Year',
    '2nd Year',
    '3rd Year',
    '4th Year',
    'Final Year',
    'Postgraduate — 1st Year',
    'Postgraduate — 2nd Year',
    'Other'
  ]);

const organizerRoles =
  new Set([
    'organizer',
    'sub_organizer'
  ]);

/* =========================================================
   CLEAN INPUT
========================================================= */

function clean(
  value,
  max = 200
) {
  return String(
    value ?? ''
  )
    .trim()
    .replace(/\s+/g, ' ')
    .slice(0, max);
}

/* =========================================================
   EMAIL VALIDATION
========================================================= */

function emailOk(email) {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(
    email
  );
}

/* =========================================================
   JSON RESPONSE
========================================================= */

function json(
  res,
  status,
  data,
  headers = {}
) {
  res.writeHead(
    status,
    {
      'Content-Type':
        'application/json; charset=utf-8',

      'Cache-Control':
        'no-store',

      ...headers
    }
  );

  return res.end(
    JSON.stringify(data)
  );
}

/* =========================================================
   REQUEST BODY
========================================================= */

async function body(req) {
  const chunks = [];

  for await (
    const chunk of req
  ) {
    chunks.push(chunk);
  }

  const raw =
    Buffer.concat(
      chunks
    ).toString('utf8');

  if (!raw) {
    return {};
  }

  try {
    return JSON.parse(raw);
  } catch {
    throw {
      status: 400,
      message:
        'Invalid JSON request.'
    };
  }
}

/* =========================================================
   PASSWORD HASHING
========================================================= */

function hashPassword(password) {
  const salt =
    crypto
      .randomBytes(16)
      .toString('hex');

  const hash =
    crypto
      .scryptSync(
        password,
        salt,
        64
      )
      .toString('hex');

  return `scrypt:${salt}:${hash}`;
}

function verifyPassword(
  password,
  stored
) {
  try {
    const parts =
      String(stored)
        .split(':');

    if (
      parts.length !== 3 ||
      parts[0] !== 'scrypt'
    ) {
      return false;
    }

    const salt =
      parts[1];

    const expected =
      Buffer.from(
        parts[2],
        'hex'
      );

    const actual =
      crypto.scryptSync(
        password,
        salt,
        64
      );

    if (
      expected.length !==
      actual.length
    ) {
      return false;
    }

    return crypto.timingSafeEqual(
      expected,
      actual
    );
  } catch {
    return false;
  }
}

/* =========================================================
   TOKEN HELPERS
========================================================= */

function createToken(prefix) {
  return `${prefix}_${crypto
    .randomBytes(32)
    .toString('hex')}`;
}

function organizerToken(email) {
  return createToken(
    `org_${Buffer
      .from(email)
      .toString('base64url')}`
  );
}

function eventToken(teamId) {
  return createToken(
    `evt_${Buffer
      .from(teamId)
      .toString('base64url')}`
  );
}

function adminToken() {
  return createToken(
    'admin'
  );
}

/* =========================================================
   COOKIE PARSER
========================================================= */

function cookies(req) {
  const header =
    req.headers.cookie || '';

  const result = {};

  for (
    const item of
    header.split(';')
  ) {
    const index =
      item.indexOf('=');

    if (index === -1) {
      continue;
    }

    const key =
      item
        .slice(0, index)
        .trim();

    const value =
      item
        .slice(index + 1)
        .trim();

    result[key] =
      decodeURIComponent(
        value
      );
  }

  return result;
}

/* =========================================================
   AUTH TOKEN STORAGE
========================================================= */

const organizerSessions =
  new Map();

const eventSessions =
  new Map();

const adminSessions =
  new Map();

/* =========================================================
   AUTH HELPERS
========================================================= */

async function authorizedOrganizer(req) {
  const c =
    cookies(req);

  const token =
    c.kgh_organizer;

  const email =
    c.kgh_organizer_email;

  if (!token || !email) {
    return null;
  }

  const session =
    organizerSessions.get(
      token
    );

  if (!session) {
    return null;
  }

  if (
    session.email !==
    String(email).toLowerCase()
  ) {
    return null;
  }

  if (
    Date.now() >
    session.expiresAt
  ) {
    organizerSessions.delete(
      token
    );

    return null;
  }

  const organizer =
    await getOrganizer(
      session.email
    );

  if (!organizer) {
    return null;
  }

  return organizer;
}

function authorizedAdmin(req) {
  const c =
    cookies(req);

  const token =
    c.kgh_admin;

  if (!token) {
    return false;
  }

  const session =
    adminSessions.get(
      token
    );

  if (!session) {
    return false;
  }

  if (
    Date.now() >
    session.expiresAt
  ) {
    adminSessions.delete(
      token
    );

    return false;
  }

  return true;
}

async function authorizedEventTeam(req) {
  const c =
    cookies(req);

  const token =
    c.kgh_event_token;

  const teamId =
    c.kgh_event_team;

  if (!token || !teamId) {
    return null;
  }

  const session =
    eventSessions.get(
      token
    );

  if (!session) {
    return null;
  }

  if (
    session.teamId !==
    teamId
  ) {
    return null;
  }

  if (
    Date.now() >
    session.expiresAt
  ) {
    eventSessions.delete(
      token
    );

    return null;
  }

  const response =
    await fetch(
      `${TEAMS_URL}?team_id=eq.${encodeURIComponent(
        teamId
      )}&select=*&limit=1`,
      {
        headers:
          supabaseHeaders()
      }
    );

  if (!response.ok) {
    return null;
  }

  const rows =
    await response.json();

  return rows[0] || null;
}

/* =========================================================
   ORGANIZER HEAD
========================================================= */

function isOrganizerHead(
  organizer
) {
  if (!organizer) {
    return false;
  }

  return (
    String(
      organizer.email || ''
    ).toLowerCase() ===
    MAIN_ORGANIZER_EMAIL
  );
}

/* =========================================================
   STATIC FILE HELPERS
========================================================= */

function contentType(file) {
  const ext =
    path
      .extname(file)
      .toLowerCase();

  const types = {
    '.html':
      'text/html; charset=utf-8',

    '.css':
      'text/css; charset=utf-8',

    '.js':
      'application/javascript; charset=utf-8',

    '.json':
      'application/json; charset=utf-8',

    '.svg':
      'image/svg+xml',

    '.png':
      'image/png',

    '.jpg':
      'image/jpeg',

    '.jpeg':
      'image/jpeg',

    '.webp':
      'image/webp',

    '.ico':
      'image/x-icon',

    '.txt':
      'text/plain; charset=utf-8'
  };

  return (
    types[ext] ||
    'application/octet-stream'
  );
}

function serve(
  res,
  relativePath
) {
  try {
    const normalized =
      path
        .normalize(relativePath)
        .replace(
          /^(\.\.(\/|\\|$))+/, 
          ''
        );

    const abs =
      path.resolve(
        PUBLIC,
        normalized
      );

    if (
      abs !== PUBLIC &&
      !abs.startsWith(
        `${PUBLIC}${path.sep}`
      )
    ) {
      return res
        .writeHead(403)
        .end();
    }

    const stat =
      fs.statSync(abs);

    if (!stat.isFile()) {
      return res
        .writeHead(404)
        .end('Not found');
    }

    const data =
      fs.readFileSync(abs);

    res.writeHead(
      200,
      {
        'Content-Type':
          contentType(abs),

        'Cache-Control':
          'no-cache'
      }
    );

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

async function getOrganizer(
  email
) {
  const url =
    `${ORGANIZERS_URL}` +
    `?select=*` +
    `&email=eq.${encodeURIComponent(
      email
    )}` +
    `&limit=1`;

  const response =
    await fetch(
      url,
      {
        headers:
          supabaseHeaders()
      }
    );

  if (!response.ok) {
    console.error(
      'Organizer lookup:',
      await response.text()
    );

    throw new Error(
      'Could not check organizer account.'
    );
  }

  const rows =
    await response.json();

  return rows[0] || null;
}

/* =========================================================
   ENSURE ORGANIZER HEAD ACCOUNT
========================================================= */

async function ensureOrganizerHead() {
  console.log(
    'Checking Organizer Head account...'
  );

  const existing =
    await getOrganizer(
      MAIN_ORGANIZER_EMAIL
    );

  /* -------------------------------------------------------
     ACCOUNT EXISTS
  ------------------------------------------------------- */

  if (existing) {

    /* Existing password hash is valid.
       Never overwrite it automatically. */

    if (
      existing.password_hash
    ) {
      console.log(
        'Organizer Head account found. Existing password hash preserved.'
      );

      return;
    }

    /* Password hash is NULL.
       Create a new hash using the Render
       environment variable. */

    console.log(
      'Organizer Head password hash is missing. Creating a new hash...'
    );

    const passwordHash =
      hashPassword(
        ORGANIZER_HEAD_PASSWORD
      );

    const response =
      await fetch(
        `${ORGANIZERS_URL}?id=eq.${encodeURIComponent(
          existing.id
        )}`,
        {
          method:
            'PATCH',

          headers:
            supabaseHeaders({
              Prefer:
                'return=representation'
            }),

          body:
            JSON.stringify({
              name:
                existing.name ||
                'Organizer Head',

              email:
                MAIN_ORGANIZER_EMAIL,

              role:
                'organizer_head',

              requested_role:
                'organizer_head',

              password_hash:
                passwordHash,

              approval_status:
                'approved'
            })
        }
      );

    if (!response.ok) {
      console.error(
        'Organizer Head password update:',
        await response.text()
      );

      throw new Error(
        'Could not initialize the Organizer Head password.'
      );
    }

    console.log(
      'Organizer Head password hash created successfully.'
    );

    return;
  }

  /* -------------------------------------------------------
     ACCOUNT DOES NOT EXIST
  ------------------------------------------------------- */

  console.log(
    'Organizer Head account not found. Creating account...'
  );

  const passwordHash =
    hashPassword(
      ORGANIZER_HEAD_PASSWORD
    );

  const response =
    await fetch(
      ORGANIZERS_URL,
      {
        method:
          'POST',

        headers:
          supabaseHeaders({
            Prefer:
              'return=representation'
          }),

        body:
          JSON.stringify({
            name:
              'Organizer Head',

            email:
              MAIN_ORGANIZER_EMAIL,

            role:
              'organizer_head',

            requested_role:
              'organizer_head',

            password_hash:
              passwordHash,

            approval_status:
              'approved'
          })
      }
    );

  if (!response.ok) {
    console.error(
      'Organizer Head creation:',
      await response.text()
    );

    throw new Error(
      'Could not create the Organizer Head account.'
    );
  }

  console.log(
    'Organizer Head account created successfully.'
  );
}

/* =========================================================
   CREATE TEAM
========================================================= */

async function createTeam(
  payload
) {
  const teamName =
    clean(
      payload.teamName,
      80
    );

  const college =
    clean(
      payload.college,
      160
    );

  const program =
    clean(
      payload.program,
      50
    );

  const department =
    clean(
      payload.department,
      100
    );

  const yearLevel =
    clean(
      payload.yearLevel,
      80
    );

  const leaderName =
    clean(
      payload.leaderName,
      100
    );

  const leaderRegNo =
    clean(
      payload.leaderRegNo,
      60
    );

  const leaderEmail =
    clean(
      payload.leaderEmail,
      160
    ).toLowerCase();

  const leaderPhone =
    clean(
      payload.leaderPhone,
      25
    );

  const member2Name =
    clean(
      payload.member2Name,
      100
    );

  const member2RegNo =
    clean(
      payload.member2RegNo,
      60
    );

  const member3Name =
    clean(
      payload.member3Name,
      100
    );

  const member3RegNo =
    clean(
      payload.member3RegNo,
      60
    );

  const member4Name =
    clean(
      payload.member4Name,
      100
    );

  const member4RegNo =
    clean(
      payload.member4RegNo,
      60
    );

  const consent =
    payload.consent === true;

  if (
    !teamName ||
    !college ||
    !program ||
    !department ||
    !yearLevel ||
    !leaderName ||
    !leaderRegNo ||
    !leaderEmail ||
    !leaderPhone
  ) {
    throw {
      status: 400,
      message:
        'Please complete all required registration fields.'
    };
  }

  if (
    !programs.has(program)
  ) {
    throw {
      status: 400,
      message:
        'Invalid program selected.'
    };
  }

  if (
    !years.has(yearLevel)
  ) {
    throw {
      status: 400,
      message:
        'Invalid academic level selected.'
    };
  }

  if (
    !emailOk(leaderEmail)
  ) {
    throw {
      status: 400,
      message:
        'Please enter a valid leader email address.'
    };
  }

  if (!consent) {
    throw {
      status: 400,
      message:
        'You must accept the declaration before registering.'
    };
  }

  const members = [
    {
      name:
        member2Name,

      regNo:
        member2RegNo
    },

    {
      name:
        member3Name,

      regNo:
        member3RegNo
    },

    {
      name:
        member4Name,

      regNo:
        member4RegNo
    }
  ];

  for (
    const member of members
  ) {
    if (
      (member.name &&
        !member.regNo) ||
      (!member.name &&
        member.regNo)
    ) {
      throw {
        status: 400,
        message:
          'Each optional member must have both a name and register number.'
      };
    }
  }

  let teamId;

  for (
    let attempt = 0;
    attempt < 10;
    attempt++
  ) {
    const candidate =
      randomTeamId();

    const check =
      await fetch(
        `${TEAMS_URL}?team_id=eq.${encodeURIComponent(
          candidate
        )}&select=team_id&limit=1`,
        {
          headers:
            supabaseHeaders()
        }
      );

    if (!check.ok) {
      throw new Error(
        'Could not verify Team ID availability.'
      );
    }

    const existing =
      await check.json();

    if (!existing.length) {
      teamId =
        candidate;

      break;
    }
  }

  if (!teamId) {
    throw new Error(
      'Could not generate a unique Team ID. Please try again.'
    );
  }

  const registration = {
    team_id:
      teamId,

    team_name:
      teamName,

    college,

    program,

    department,

    year_level:
      yearLevel,

    leader_name:
      leaderName,

    leader_reg_no:
      leaderRegNo,

    leader_email:
      leaderEmail,

    leader_phone:
      leaderPhone,

    member2_name:
      member2Name || null,

    member2_reg_no:
      member2RegNo || null,

    member3_name:
      member3Name || null,

    member3_reg_no:
      member3RegNo || null,

    member4_name:
      member4Name || null,

    member4_reg_no:
      member4RegNo || null
  };

  const response =
    await fetch(
      TEAMS_URL,
      {
        method:
          'POST',

        headers:
          supabaseHeaders({
            Prefer:
              'return=representation'
          }),

        body:
          JSON.stringify(
            registration
          )
      }
    );

  if (!response.ok) {
    console.error(
      'Registration:',
      await response.text()
    );

    throw new Error(
      'Could not save registration. Please try again.'
    );
  }

  return {
    ok: true,
    teamId
  };
}

/* =========================================================
   EVENT LOGIN
========================================================= */

async function eventLogin(
  payload
) {
  const teamId =
    clean(
      payload.teamId,
      20
    ).toUpperCase();

  if (!teamId) {
    throw {
      status: 400,
      message:
        'Please enter your Team ID.'
    };
  }

  const response =
    await fetch(
      `${TEAMS_URL}?team_id=eq.${encodeURIComponent(
        teamId
      )}&select=*&limit=1`,
      {
        headers:
          supabaseHeaders()
      }
    );

  if (!response.ok) {
    throw new Error(
      'Could not verify Team ID.'
    );
  }

  const rows =
    await response.json();

  const team =
    rows[0];

  if (!team) {
    throw {
      status: 401,
      message:
        'Team ID not found. Please check your Team ID.'
    };
  }

  const token =
    eventToken(
      team.team_id
    );

  eventSessions.set(
    token,
    {
      teamId:
        team.team_id,

      expiresAt:
        Date.now() +
        4 * 60 * 60 * 1000
    }
  );

  return {
    team,
    token
  };
}

/* =========================================================
   ORGANIZER REQUEST
========================================================= */

async function requestOrganizer(
  payload
) {
  const name =
    clean(
      payload.name,
      100
    );

  const email =
    clean(
      payload.email,
      160
    ).toLowerCase();

  const requestedRole =
    clean(
      payload.requestedRole ||
      payload.role ||
      'organizer',
      40
    );

  const password =
    String(
      payload.password || ''
    );

  if (
    !name ||
    !email ||
    !password
  ) {
    throw {
      status: 400,
      message:
        'Please complete all organizer application fields.'
    };
  }

  if (
    !emailOk(email)
  ) {
    throw {
      status: 400,
      message:
        'Please enter a valid email address.'
    };
  }

  if (
    password.length < 8
  ) {
    throw {
      status: 400,
      message:
        'Organizer password must be at least 8 characters.'
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
        'Invalid organizer role.'
    };
  }

  if (
    email ===
    MAIN_ORGANIZER_EMAIL
  ) {
    throw {
      status: 409,
      message:
        'This email is reserved for the Organizer Head account.'
    };
  }

  const existing =
    await getOrganizer(
      email
    );

  const passwordHash =
    hashPassword(
      password
    );

  if (existing) {
    if (
      existing.approval_status ===
      'approved'
    ) {
      throw {
        status: 409,
        message:
          'An approved organizer account already exists for this email.'
      };
    }

    const response =
      await fetch(
        `${ORGANIZERS_URL}?id=eq.${encodeURIComponent(
          existing.id
        )}`,
        {
          method:
            'PATCH',

          headers:
            supabaseHeaders({
              Prefer:
                'return=representation'
            }),

          body:
            JSON.stringify({
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

              approved_by:
                null,

              approved_at:
                null
            })
        }
      );

    if (!response.ok) {
      console.error(
        'Organizer request update:',
        await response.text()
      );

      throw new Error(
        'Could not submit organizer request.'
      );
    }
  } else {
    const response =
      await fetch(
        ORGANIZERS_URL,
        {
          method:
            'POST',

          headers:
            supabaseHeaders({
              Prefer:
                'return=representation'
            }),

          body:
            JSON.stringify({
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

              approved_by:
                null,

              approved_at:
                null
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

async function organizerLogin(
  payload
) {
  const email =
    clean(
      payload.email,
      160
    ).toLowerCase();

  const password =
    String(
      payload.password || ''
    );

  if (
    !email ||
    !password
  ) {
    throw {
      status: 400,
      message:
        'Please enter your organizer email and password.'
    };
  }

  if (
    !emailOk(email)
  ) {
    throw {
      status: 400,
      message:
        'Please enter a valid email address.'
    };
  }

  const organizer =
    await getOrganizer(
      email
    );

  if (!organizer) {
    throw {
      status: 401,
      message:
        'No organizer account was found for this email.'
    };
  }

  if (
    !organizer.password_hash
  ) {
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
    isOrganizerHead(
      organizer
    );

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
  const response =
    await fetch(
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

  const response =
    await fetch(
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
      `${ORGANIZERS_URL}?id=eq.${encodeURIComponent(
        id
      )}&select=*`,
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

  const target =
    rows[0];

  if (!target) {
    throw {
      status: 404,
      message:
        'Organizer account not found.'
    };
  }

  if (
    String(
      target.email || ''
    ).toLowerCase() ===
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
      `${ORGANIZERS_URL}?id=${encodeURIComponent(
        id
      )}`,
      {
        method:
          'PATCH',

        headers:
          supabaseHeaders({
            Prefer:
              'return=representation'
          }),

        body:
          JSON.stringify(
            update
          )
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

const server =
  createServer(
    async (
      req,
      res
    ) => {
      try {
        const url =
          new URL(
            req.url,
            `http://${req.headers.host || 'localhost'}`
          );

        const p =
          url.pathname;

        /* =================================================
           HEALTH CHECK
        ================================================= */

        if (
          req.method === 'GET' &&
          p === '/health'
        ) {
          return json(
            res,
            200,
            {
              ok: true,

              service:
                'kravens-gate-heist'
            }
          );
        }

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

          const token =
            result.token;

          organizerSessions.set(
            token,
            {
              email:
                result.organizer.email
                  .toLowerCase(),

              expiresAt:
                Date.now() +
                8 * 60 * 60 * 1000
            }
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
            await authorizedOrganizer(
              req
            );

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
          const c =
            cookies(req);

          if (
            c.kgh_organizer
          ) {
            organizerSessions.delete(
              c.kgh_organizer
            );
          }

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

              team:
                result.team
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
            await authorizedEventTeam(
              req
            );

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
          const c =
            cookies(req);

          if (
            c.kgh_event_token
          ) {
            eventSessions.delete(
              c.kgh_event_token
            );
          }

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
           ADMIN LOGIN
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

          const token =
            adminToken();

          adminSessions.set(
            token,
            {
              expiresAt:
                Date.now() +
                8 * 60 * 60 * 1000
            }
          );

          return json(
            res,
            200,
            {
              ok: true
            },
            {
              'Set-Cookie':
                `kgh_admin=${token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800`
            }
          );
        }

        /* =================================================
           PROTECTED ADMIN API
        ================================================= */

        if (
          p.startsWith(
            '/api/admin/'
          )
        ) {
          const organizer =
            await authorizedOrganizer(
              req
            );

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
            /^\/api\/admin\/organizers\/[^/]+\/(approve|reject)$/.test(
              p
            )
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
                  'attachment; filename="kravens-gate-heist-registrations.csv"',

                'Cache-Control':
                  'no-store'
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

          if (
            p === '/admin'
          ) {
            return serve(
              res,
              'admin.html'
            );
          }

          if (
            p === '/organizer'
          ) {
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

          if (
            p === '/event'
          ) {
            return serve(
              res,
              'event.html'
            );
          }

          if (
            p === '/round'
          ) {
            return serve(
              res,
              'round.html'
            );
          }

          if (
            p === '/result'
          ) {
            return serve(
              res,
              'result.html'
            );
          }

          if (
            p === '/final'
          ) {
            return serve(
              res,
              'final.html'
            );
          }

          if (
            p === '/projector'
          ) {
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

        return res
          .writeHead(404)
          .end('Not found');

      } catch (error) {
        console.error(
          'SERVER ERROR:',
          error
        );

        if (
          error?.status
        ) {
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

async function startServer() {
  /* -------------------------------------------------------
     Initialize Organizer Head before accepting requests.
  ------------------------------------------------------- */

  await ensureOrganizerHead();

  server.listen(
    PORT,
    '0.0.0.0',
    () => {
      console.log(
        `KGH registration running on port ${PORT}`
      );
    }
  );
}

startServer().catch(
  error => {
    console.error(
      'SERVER STARTUP ERROR:',
      error
    );

    process.exit(1);
  }
);
```

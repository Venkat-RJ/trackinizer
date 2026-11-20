"""Add bearer-token browser sign-in to Trackinizer without disabling API authentication."""
import html
import os
import sys
from urllib.parse import parse_qs

from fastapi import Request
from fastapi.responses import HTMLResponse, RedirectResponse
from starlette.exceptions import HTTPException
from starlette.requests import Request as Probe
from trackinizer.server import server
from trackinizer.server.auth import request_user
from trackinizer.server.session import set_session_cookie


def destination(path: str) -> str:
    if not path.startswith('/') or path.startswith('//') or any(c in path for c in '\r\n\\'):
        return '/trax/'
    return path if len(path) < 512 else '/trax/'


def page(next_url='/trax/', failed=False):
    message = '<p style="color:#b42318">Invalid token or user.</p>' if failed else ''
    markup = f'''<!doctype html><html><head><meta name="viewport" content="width=device-width,initial-scale=1"><title>Trackinizer sign in</title><style>body{{font:16px system-ui;background:#edf2f7;display:grid;place-items:center;min-height:90vh}}main{{background:white;border:1px solid #ccd6df;border-radius:14px;padding:34px;width:min(420px,85vw)}}input,button{{box-sizing:border-box;display:block;width:100%;padding:12px;font:inherit;margin:12px 0}}button{{background:#1961ac;color:white;border:0;border-radius:7px}}</style></head><body><main><h1>Trackinizer</h1><p>Sign in using your personal API token.</p>{message}<form action="/auth/token-login" method="POST"><input type="hidden" name="next" value="{html.escape(destination(next_url),quote=True)}"><label for="token">API token</label><input id="token" name="token" type="password" maxlength="180" required autocomplete="off"><button type="submit">Sign in</button></form><small>Keep this token secret. Use only HTTPS.</small></main></body></html>'''
    return HTMLResponse(markup,status_code=401 if failed else 200,headers={'Cache-Control':'no-store','Referrer-Policy':'same-origin','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"})


async def sign_in_page(request: Request):
    return page(request.query_params.get('next','/trax/'))


async def sign_in(request: Request):
    data=await request.body()
    if len(data)>2048: return page(failed=True)
    try:
        fields=parse_qs(data.decode(),keep_blank_values=True)
        token=fields.get('token',[''])[0]
        next_url=destination(fields.get('next',['/trax/'])[0])
        raw_token=token.encode('ascii')
    except (UnicodeError,ValueError): return page(failed=True)
    if not token.startswith('trax_') or not 20<=len(token)<=180:
        return page(next_url,True)
    scope=request.scope.copy()
    scope['headers']=[(k,v) for k,v in scope['headers'] if k.lower()!=b'authorization']+[(b'authorization',b'Bearer '+raw_token)]
    try: actor=await request_user(Probe(scope,receive=request.receive))
    except HTTPException: return page(next_url,True)
    if actor.email.endswith('@service.invalid'): return page(next_url,True)
    # Do not upgrade a restricted key to its owner's full browser permissions.
    async with request.app.state.engine.acquire() as db:
        row=await db.fetchrow('SELECT u.session_generation, u.role, k.open_into FROM users u JOIN api_keys k ON k.user_id=u.id WHERE u.id=$1 AND k.id=$2',actor.user_id,actor.api_key_id)
    if row is None or actor.role != row['role'] or row['open_into'] is not None:
        return page(next_url,True)
    generation=row['session_generation']
    cfg=request.app.state.config
    if not cfg.session_secret: raise RuntimeError('Configure TRACKINIZER_SESSION_SECRET_FILE')
    response=RedirectResponse(next_url,status_code=303,headers={'Cache-Control':'no-store'})
    set_session_cookie(response,user_id=str(actor.user_id),generation=int(generation),secret=cfg.session_secret,max_age_seconds=cfg.session_max_age_seconds)
    return response


# Registered before the upstream unconfigured login page.
server.app.add_api_route('/auth/login_page',sign_in_page,methods=['GET'],include_in_schema=False)
server.app.add_api_route('/auth/token-login',sign_in,methods=['POST'],include_in_schema=False)

# Private, admin-only onboarding for another human collaborator.
import re
import uuid
from trackinizer.server.auth import create_api_key
from trackinizer.server.notify import tx


def invite_page(info="", issued=None):
    intro = "<p>Create a writer account and one private sign-in token.</p>"
    if issued is not None:
        address, token = issued
        intro = (
            "<h2>Invite created</h2><p>Send this token privately to "
            + html.escape(address) +
            ". It is displayed only once and cannot be recovered later.</p>"
            + "<textarea readonly spellcheck='false' rows='4' "
            + "style='width:100%;box-sizing:border-box;font:13px monospace'>"
            + html.escape(token) + "</textarea><p>Teammate sign-in: "
            + "<a href='/auth/login_page'>/auth/login_page</a></p>"
        )
    form = (
        "<form method='post' action='/auth/invite'>"
        "<label>Email address</label>"
        "<input type='email' name='email' maxlength='254' required>"
        "<button>Create writer invitation</button></form>"
    ) if issued is None else "<a href='/auth/invite'>Invite another teammate</a>"
    out = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>Invite teammate | Trackinizer</title>'
        '<style>body{font:16px system-ui;background:#edf2f7;display:grid;'
        'place-items:center;min-height:90vh}main{background:#fff;'
        'border:1px solid #ccd6df;border-radius:14px;padding:34px;'
        'width:min(490px,85vw)}input,button{box-sizing:border-box;'
        'display:block;width:100%;padding:12px;font:inherit;margin:12px 0}'
        'button{background:#1961ac;color:white;border:0;border-radius:7px}'
        'textarea{background:#f2f5f8;padding:8px}p{line-height:1.5}</style>'
        '</head><body><main><h1>Invite teammate</h1>'
        + intro + ("<p role='alert'>" + html.escape(info) + "</p>" if info else "")
        + form + '<p><small>Writer access only. Do not share your admin token.</small></p>'
        + '</main></body></html>'
    )
    return HTMLResponse(
        out,
        headers={
            "Cache-Control":"no-store",
            "Referrer-Policy":"same-origin",
            "X-Frame-Options":"DENY",
            "Content-Security-Policy":"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
        },
    )


async def _invite_admin(request):
    actor = await request_user(request)
    if actor.role != "admin":
        raise HTTPException(status_code=403, detail="admin only")
    return actor


async def invite_form(request: Request):
    await _invite_admin(request)
    return invite_page()


async def invite_create(request: Request):
    actor = await _invite_admin(request)
    data = await request.body()
    if len(data) > 1024:
        return invite_page("Email too long.")
    try:
        email = parse_qs(data.decode("utf-8"), keep_blank_values=True).get("email", [""])[0].strip().lower()
    except UnicodeError:
        return invite_page("Invalid email address.")
    if (
        len(email) > 254
        or re.fullmatch(r"[a-z0-9._%+\-]+@[a-z0-9.-]+\.[a-z]{2,}", email) is None
        or email.endswith("@service.invalid")
        or email == actor.email.lower()
    ):
        return invite_page("Enter your teammate's email address.")
    async with request.app.state.engine.acquire() as db, tx(db):
        existing = await db.fetchrow(
            "SELECT id, role, status FROM users WHERE email=$1 FOR UPDATE", email
        )
        if existing is None:
            user_id = uuid.uuid4()
            await db.execute(
                "INSERT INTO users (id,email,name,role,status) VALUES ($1,$2,$3,'writer','active')",
                user_id, email, email.split("@")[0][:100],
            )
            await request.app.state.store.access_policy.on_user(db,email=email,role="writer")
        elif existing["role"] != "writer" or existing["status"] != "active":
            return invite_page("This email belongs to an account that is not an active writer.")
        else:
            user_id = existing["id"]
        await db.execute(
            "INSERT INTO allowlist (email_or_pattern,role,added_by) "
            "VALUES ($1,'writer',$2) ON CONFLICT (email_or_pattern) DO NOTHING",
            email, actor.user_id,
        )
        key_id, secret, prefix, role = await create_api_key(
            db, user_id=user_id, name="team-invite",
            role="writer", ceiling="writer",
        )
    return invite_page(issued=(email,secret))


server.app.add_api_route('/auth/invite',invite_form,methods=['GET'],include_in_schema=False)
server.app.add_api_route('/auth/invite',invite_create,methods=['POST'],include_in_schema=False)

if __name__=='__main__':
    sys.argv=['trackinizer','--engine','pglite','--datadir','/data/pgdata','--host','0.0.0.0','--port',os.getenv('PORT','8765'),'--auth']
    raise SystemExit(server.main())

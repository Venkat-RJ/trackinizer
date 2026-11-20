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
    return HTMLResponse(markup,status_code=401 if failed else 200,headers={'Cache-Control':'no-store','Referrer-Policy':'no-referrer','Content-Security-Policy':"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'"})


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
if __name__=='__main__':
    sys.argv=['trackinizer','--engine','pglite','--datadir','/data/pgdata','--host','0.0.0.0','--port',os.getenv('PORT','8765'),'--auth']
    raise SystemExit(server.main())

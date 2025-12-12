from urllib.parse import parse_qs
from channels.middleware import BaseMiddleware
from channels.db import database_sync_to_async
import jwt
from django.conf import settings
 
@database_sync_to_async
def get_user_model_and_user(user_id):
    from django.contrib.auth import get_user_model
    User = get_user_model()
    try:
        return User.objects.get(id=user_id)
    except User.DoesNotExist:
        return None
 
class TokenAuthMiddleware(BaseMiddleware):
    async def __call__(self, scope, receive, send):
        # query string থেকে token
        query_string = parse_qs(scope["query_string"].decode())
        token = query_string.get("token", [None])[0]
 
        # header থেকে token check
        headers = dict((k.decode().lower(), v.decode()) for k, v in scope.get("headers", []))
        auth_header = headers.get("authorization")
        if auth_header and auth_header.startswith("Bearer "):
            token = auth_header.split(" ")[1]
 
        # debug: print token
        print("Token from header/query:", token)
 
        # token decode
        if token:
            try:
                payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
                scope["user"] = await get_user_model_and_user(payload.get("user_id"))
            except (jwt.ExpiredSignatureError, jwt.DecodeError):
                scope["user"] = None
        else:
            scope["user"] = None
 
        return await super().__call__(scope, receive, send)
 

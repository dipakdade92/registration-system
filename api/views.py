from datetime import datetime, timedelta  # Correct imports

import jwt
from rest_framework import status
from rest_framework.decorators import api_view
from rest_framework.exceptions import ValidationError
from rest_framework.response import Response

from mongo_auth import messages
from mongo_auth.db import (
    auth_collection,
    database,
    fields,
    jwt_life,
    jwt_secret,
    secondary_username_field,
)
from mongo_auth.utils import create_unique_object_id, pwd_context


def get_user_by_email(email):
    return database[auth_collection].find_one({"email": email}, {"_id": 0})


def get_user_by_secondary_field(value):
    return database[auth_collection].find_one(
        {secondary_username_field: value}, {"_id": 0}
    )


def create_jwt_token(user):
    return jwt.encode(
        {
            "id": user["id"],
            "username": user.get("username"),
            "email": user["email"],
            "exp": datetime.utcnow() + timedelta(days=jwt_life),
        },
        jwt_secret,
        algorithm="HS256",
    )


@api_view(["POST"])
def signup(request):
    try:
        data = request.data or {}
        signup_data = {"id": create_unique_object_id()}
        all_fields = set(fields + ("email", "password"))

        if secondary_username_field:
            all_fields.add(secondary_username_field)

        for field in all_fields:
            if field not in data:
                return Response(
                    status=status.HTTP_400_BAD_REQUEST,
                    data={"error_msg": f"{field.title()} does not exist."},
                )
            signup_data[field] = data[field]

        signup_data["password"] = pwd_context.hash(signup_data["password"])

        if get_user_by_email(signup_data["email"]) is None:
            if secondary_username_field and get_user_by_secondary_field(
                signup_data[secondary_username_field]
            ):
                return Response(
                    status=status.HTTP_405_METHOD_NOT_ALLOWED,
                    data={
                        "error_msg": messages.user_exists_field(
                            secondary_username_field
                        )
                    },
                )

            database[auth_collection].insert_one(signup_data)
            res = {k: v for k, v in signup_data.items() if k not in ["_id", "password"]}
            return Response(status=status.HTTP_200_OK, data={"data": res})

        return Response(
            status=status.HTTP_405_METHOD_NOT_ALLOWED,
            data={"error_msg": messages.user_exists},
        )
    except ValidationError as v_error:
        return Response(
            status=status.HTTP_400_BAD_REQUEST, data={"message": str(v_error)}
        )
    except Exception as e:
        return Response(
            status=status.HTTP_500_INTERNAL_SERVER_ERROR, data={"error_msg": str(e)}
        )


@api_view(["POST"])
def login(request):
    try:
        data = request.data or {}
        username = data.get("username")
        password = data.get("password")

        user = (
            get_user_by_email(username)
            if "@" in username
            else get_user_by_secondary_field(username)
        )

        if user and pwd_context.verify(password, user.get("password")):
            token = create_jwt_token(user)
            return Response(
                status=status.HTTP_200_OK,
                data={
                    "data": {
                        "token": token,
                        "username": user.get("username"),
                        "email": user.get("email"),
                    }
                },
            )

        return Response(
            status=status.HTTP_403_FORBIDDEN,
            data={
                "error_msg": (
                    messages.incorrect_password if user else messages.user_not_found
                )
            },
        )
    except ValidationError as v_error:
        return Response(
            status=status.HTTP_400_BAD_REQUEST, data={"message": str(v_error)}
        )
    except Exception as e:
        return Response(
            status=status.HTTP_500_INTERNAL_SERVER_ERROR, data={"error_msg": str(e)}
        )

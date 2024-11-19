from rest_framework import generics
from rest_framework.permissions import AllowAny
from .permissions import IsAdmin
from .models import User
from .serializers import UserSerializer

import logging
from django.utils.timezone import now


class RegisterUserView(generics.CreateAPIView):
    """
        post:
        Register a new user.

        Request body:
        - `username`: The desired username for the user.
        - `email`: The email address of the user.
        - `password`: The password for the account.
        - `role`: The role of the user (e.g., 'student', 'teacher', 'admin').

        Response:
        - `id`: The ID of the created user.
        - `username`: The username of the created user.
        - `email`: The email of the created user.
        - `role`: The role of the created user.
        """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [AllowAny]

    def perform_create(self, serializer):
        user = serializer.save()
        logger = logging.getLogger('custom')
        logger.info(f"New user registered: {user.email} at {now()}")


class UserListView(generics.ListAPIView):
    """
        get:
        Retrieve a list of all registered users. Only accessible to admins.

        Response:
        - List of user objects, each containing:
          - `id`: The ID of the user.
          - `username`: The username.
          - `email`: The email address.
          - `role`: The user's role.
        """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdmin]

    def list(self, request, *args, **kwargs):
        logger = logging.getLogger('custom')
        logger.info(f"Admin {request.user.email} requested user list.")
        return super().list(request, *args, **kwargs)


class UserDetailView(generics.RetrieveUpdateDestroyAPIView):
    """
        get:
        Retrieve the details of a specific user by their ID.

        put:
        Update the details of a specific user. Only accessible to admins.

        delete:
        Delete a user by their ID.

        Parameters:
        - `id`: The ID of the user.

        Response:
        - The updated or retrieved user details.
        """
    queryset = User.objects.all()
    serializer_class = UserSerializer
    permission_classes = [IsAdmin]



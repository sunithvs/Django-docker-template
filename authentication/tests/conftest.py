# conftest.py at the project root

import pytest

from authentication.models import User


# Define a fixture that creates a test user
@pytest.fixture
def user(db):
    return User.objects.create(email='test@example.com', password='password')

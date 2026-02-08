from django.db import models
from django.contrib.auth.models import User
import hashlib

import random
from django.db import models
from django.contrib.auth.models import User
from django.utils import timezone

from django.utils import timezone
from datetime import timedelta
import random

class OTP(models.Model):
    email = models.EmailField()
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        return timezone.now() <= self.created_at + timedelta(minutes=5)

    @staticmethod
    def generate():
        return str(random.randint(100000, 999999))

class OTP(models.Model):
    email = models.EmailField()
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)

    def is_valid(self):
        return timezone.now() <= self.created_at + timezone.timedelta(minutes=5)

    def __str__(self):
        return f"{self.email} - {self.code}"

class SecureFile(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    file = models.FileField(upload_to="secure_files/")
    uploaded_at = models.DateTimeField(auto_now_add=True)

    # TRASH
    is_deleted = models.BooleanField(default=False)
    deleted_at = models.DateTimeField(null=True, blank=True)
    deleted_by = models.ForeignKey(
        User,
        null=True,
        blank=True,
        related_name="deleted_files",
        on_delete=models.SET_NULL
    )

    # EXTRA
    is_starred = models.BooleanField(default=False)

    # INTEGRITY
    sha256 = models.CharField(max_length=64, blank=True)
    integrity_verified = models.BooleanField(default=True)

    def save(self, *args, **kwargs):
        if self.file and not self.sha256:
            hasher = hashlib.sha256()
            for chunk in self.file.chunks():
                hasher.update(chunk)
            self.sha256 = hasher.hexdigest()
        super().save(*args, **kwargs)

    def __str__(self):
        return self.file.name


class AuditLog(models.Model):
    user = models.ForeignKey(
        User,
        null=True,
        blank=True,
        on_delete=models.SET_NULL
    )
    action = models.CharField(max_length=100)
    file = models.ForeignKey(
        SecureFile,
        null=True,
        blank=True,
        on_delete=models.SET_NULL
    )
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.action}"


class UserSecurity(models.Model):
    user = models.OneToOneField(User, on_delete=models.CASCADE)
    is_flagged = models.BooleanField(default=False)
    disabled_until = models.DateTimeField(null=True, blank=True)
    notes = models.TextField(blank=True)

    def __str__(self):
        return self.user.username
from django.utils import timezone
from datetime import timedelta
import random

from django.db import models
from django.utils import timezone
from datetime import timedelta

class OTP(models.Model):
    email = models.EmailField()
    code = models.CharField(max_length=6)
    created_at = models.DateTimeField(auto_now_add=True)
    attempts = models.IntegerField(default=0)

    def is_valid(self):
        return (
            timezone.now() <= self.created_at + timedelta(minutes=5)
            and self.attempts < 5
        )

    def __str__(self):
        return f"{self.email} - {self.code}"

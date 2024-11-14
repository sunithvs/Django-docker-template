from django.contrib import admin
from django.utils.safestring import mark_safe

from authentication.models import User


def is_sha256_hash(text):
    # Check if the text contains 'sha256' substring
    if 'sha256' not in text:
        return False
    return True


@admin.register(User)
class UserAdmin(admin.ModelAdmin):
    list_display = ('email', 'full_name', 'is_active', 'is_staff', 'is_superuser', 'avatar')
    list_filter = ('is_active', 'is_staff', 'is_superuser', 'groups', )
    search_fields = ('email', 'full_name',)
    ordering = ('email',)
    fieldsets = (
        (None, {'fields': ('email', 'password')}),
        ('Personal info', {'fields': ('full_name', 'profile')}),
        ('Permissions', {'fields': ('is_active', 'is_staff', 'is_superuser', 'groups')}),
        ('Important dates', {'fields': ('last_login', 'date_joined')}),
    )

    def save_model(self, request, obj, form, change):
        # Get the password from the form if provided
        password = form.cleaned_data.get('password')
        if password:
            if not is_sha256_hash(password):
                obj.set_password(password)
            else:
                obj.password = password
        elif 'password' in form.changed_data:
            # If password field is modified but no new password is provided, ignore the password field
            form.cleaned_data.pop('password', None)

        super().save_model(request, obj, form, change)

    def avatar(self, obj):
        return mark_safe(f'<img src="{obj.profile}" width="50" height="50" />')

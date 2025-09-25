from django.contrib import admin
from .models import *

# Register your models here.

class AdminProblems(admin.ModelAdmin):
    pass

admin.register(Problem, AdminProblems)
"""
URL configuration for LearnPrograms project.

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/5.2/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.contrib import admin
from django.urls import path
from LearnApp import views
from django.contrib import admin
from django.urls import path
from LearnApp import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.login_view, name='login'),
    path('home/', views.home, name='home'),
    path('problems/', views.problems, name='problems'),
    path('problems/my-problems/', views.user_problems, name='user_problems'),
    path('problems/create/', views.create_problem, name='create_problem'),
    path('problems/<int:problem_id>/test-cases/', views.add_test_cases, name='add_test_cases'),
    path('test-cases/<int:test_case_id>/edit/', views.edit_test_case, name='edit_test_case'),
    path('test-cases/<int:test_case_id>/delete/', views.delete_test_case, name='delete_test_case'),
    path('problems/<int:problem_id>/solutions/', views.add_solutions, name='add_solutions'),
    path('problems/<int:problem_id>/', views.problem_detail, name='problem_detail'),
    path('problems/<int:problem_id>/submit/', views.submit_solution, name='submit_solution'),
    path('submission/<int:submission_id>/', views.submission_result, name='submission_result'),
    path('contests/', views.contests, name='contests'),
    path('leaderboard/', views.leaderboard, name='leaderboard'),
    path('about/', views.about, name='about'),
    path('profile/', views.profile, name='profile'),
    path('submissions/', views.submissions, name='submissions'),
    path('logout/', views.logout, name='logout')
]
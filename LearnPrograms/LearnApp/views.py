import secrets

from django.contrib.auth.hashers import make_password
from django.core.exceptions import PermissionDenied
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import HttpResponse, JsonResponse, HttpResponseForbidden
from django.contrib.auth.decorators import login_required
from django.core.mail import send_mail
from django.conf import settings
from django.views.decorators.http import require_POST

from .judge.sandbox import run_sandboxed
from .models import *
from .forms import *
import random
import json
from datetime import datetime, timedelta
import os, re, shutil, subprocess, sys, tempfile, logging

from .utils.throttle import (get_client_ip, throttle, gen_code,
                       code_is_fresh, bump_attempt,
                       CODE_TTL, MAX_CODE_ATTEMPTS)

import signal as _signal

# ДЛЯ КОДА
DEFAULT_LIMITS = dict(mem_mb=256, fsize_mb=16, nproc=32)
JAVA_LIMITS    = dict(mem_mb=512, fsize_mb=16, nproc=64)
COMPILE_LIMITS = dict(mem_mb=1024, fsize_mb=64, nproc=128)

logger = logging.getLogger(__name__)

# ДЛЯ ЗАШИТЫ ОТ СПАМА
ACTION_LIMITS = {
    'login':              (5,  60),    # 5 логинов / мин с IP
    'signup':             (5,  300),   # 5 регистраций / 5 мин с IP
    'verify_signup':      (10, 300),
    'verify_login':       (10, 300),
    'resend_signup_code': (3,  300),
    'resend_login_code':  (3,  300),
    'forgot_password':    (3,  600),
    'reset_password':     (10, 600),
    'resend_reset_code':  (3,  600),
}

EMAIL_ACTIONS = {
    'signup', 'resend_signup_code', 'resend_login_code',
    'forgot_password', 'resend_reset_code',
}
EMAIL_LIMIT = (3, 600)   # 3 письма / 10 мин на адрес

SIGNUP_SESSION_KEYS = ('verification_code', 'signup_data',
                       'verification_time', 'signup_code_attempts')
LOGIN_SESSION_KEYS = ('login_verification_code', 'login_user_id',
                      'login_verification_time', 'login_code_attempts')
RESET_SESSION_KEYS = ('reset_code', 'reset_email',
                      'reset_time', 'reset_code_attempts')

def _clear_session(request, keys):
    for k in keys:
        request.session.pop(k, None)
    request.session.modified = True

def _as_text(value):
    if value is None:
        return ''
    if isinstance(value, bytes):
        return value.decode('utf-8', errors='replace')
    return str(value)

def _too_many(retry):
    return JsonResponse({
        'success': False,
        'message': f'Слишком много запросов. Повторите через {retry} сек.'
    }, status=429)

def login_view(request):
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == "POST":
        action = request.POST.get('action')
        ip = get_client_ip(request)

        # --- Лимит по IP для действия ---
        limits = ACTION_LIMITS.get(action)
        if limits:
            allowed, retry = throttle(f'{action}:ip:{ip}', *limits)
            if not allowed:
                return _too_many(retry)

        # --- Отдельный лимит на отправку писем по адресу ---
        if action in EMAIL_ACTIONS:
            email = (request.POST.get('email') or '').strip().lower()
            if email:
                allowed, retry = throttle(f'{action}:email:{email}', *EMAIL_LIMIT)
                if not allowed:
                    return _too_many(retry)

        # ---------------- LOGIN ----------------
        if action == 'login':
            username = (request.POST.get('username') or '').strip()
            password = request.POST.get('password') or ''

            if '@' in username:
                user_obj = User.objects.filter(email__iexact=username).first()
                if user_obj:
                    username = user_obj.username

            user = authenticate(request, username=username, password=password)
            if user is None:
                # Не раскрываем, существует ли аккаунт
                return JsonResponse({
                    'success': False,
                    'message': 'Неверный логин/email или пароль.'
                })

            # Дополнительный лимит по конкретному пользователю
            allowed, retry = throttle(f'login:user:{user.id}', 10, 300)
            if not allowed:
                return _too_many(retry)

            verification_code = gen_code()
            request.session['login_verification_code'] = verification_code
            request.session['login_user_id'] = user.id
            request.session['login_verification_time'] = datetime.now().isoformat()
            request.session['login_code_attempts'] = 0
            request.session.modified = True

            try:
                send_mail(
                    'Verify Your Login - CodeSport',
                    f'Your login verification code is: {verification_code}\n\n'
                    f'This code will expire in 10 minutes.\n\n'
                    f'If you did not attempt to login, please ignore this email.',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
            except Exception:
                _clear_session(request, LOGIN_SESSION_KEYS)
                return JsonResponse({
                    'success': False,
                    'message': 'Не удалось отправить код. Попробуйте позже.'
                })

            # Пароль больше НЕ уходит клиенту и НЕ лежит в сессии
            return JsonResponse({
                'requires_verification': True,
                'username': username,
                'email': user.email,
            })

        # ---------------- SIGNUP ----------------
        elif action == 'signup':
            username = (request.POST.get('username') or '').strip()
            email = (request.POST.get('email') or '').strip().lower()
            password = request.POST.get('password') or ''
            confirm_password = request.POST.get('confirm_password') or ''

            if not username or not email or not password:
                return JsonResponse({'success': False, 'message': 'Заполните все поля.'})
            if password != confirm_password:
                return JsonResponse({'success': False, 'message': 'Пароли не совпадают.'})
            if len(password) < 8:
                return JsonResponse({'success': False, 'message': 'Пароль слишком короткий.'})
            if User.objects.filter(username__iexact=username).exists():
                return JsonResponse({'success': False, 'message': 'Имя пользователя занято.'})
            if User.objects.filter(email__iexact=email).exists():
                return JsonResponse({'success': False, 'message': 'Email уже зарегистрирован.'})

            verification_code = gen_code()
            request.session['verification_code'] = verification_code
            request.session['signup_data'] = {
                'username': username,
                'email': email,
                # Храним ХЭШ, а не открытый пароль
                'password_hash': make_password(password),
            }
            request.session['verification_time'] = datetime.now().isoformat()
            request.session['signup_code_attempts'] = 0
            request.session.modified = True

            try:
                send_mail(
                    'Verify Your Email - CodeSport',
                    f'Your verification code is: {verification_code}\n\n'
                    f'This code will expire in 10 minutes.',
                    settings.DEFAULT_FROM_EMAIL,
                    [email],
                    fail_silently=False,
                )
            except Exception:
                _clear_session(request, SIGNUP_SESSION_KEYS)
                return JsonResponse({
                    'success': False,
                    'message': 'Не удалось отправить письмо. Попробуйте позже.'
                })

            return JsonResponse({'success': True, 'email': email, 'username': username})

        # ---------------- VERIFY SIGNUP ----------------
        elif action == 'verify_signup':
            verification_code = (request.POST.get('verification_code') or '').strip()
            signup_data = request.session.get('signup_data')
            stored_code = request.session.get('verification_code')

            if not stored_code or not signup_data:
                return JsonResponse({
                    'success': False,
                    'message': 'Сессия истекла. Зарегистрируйтесь заново.'
                })

            if not code_is_fresh(request.session, 'verification_time'):
                _clear_session(request, SIGNUP_SESSION_KEYS)
                return JsonResponse({'success': False, 'message': 'Код истёк.'})

            if bump_attempt(request.session, 'signup_code_attempts') > MAX_CODE_ATTEMPTS:
                _clear_session(request, SIGNUP_SESSION_KEYS)
                return JsonResponse({'success': False, 'message': 'Слишком много попыток.'})

            if not secrets.compare_digest(verification_code, stored_code):
                return JsonResponse({'success': False, 'message': 'Неверный код.'})

            try:
                user = User(
                    username=signup_data['username'],
                    email=signup_data['email'],
                )
                user.password = signup_data['password_hash']
                user.save()
            except Exception:
                return JsonResponse({'success': False, 'message': 'Не удалось создать аккаунт.'})

            _clear_session(request, SIGNUP_SESSION_KEYS)
            auth_login(request, user)
            return JsonResponse({'success': True, 'redirect_url': '/home/'})

        # ---------------- VERIFY LOGIN ----------------
        elif action == 'verify_login':
            verification_code = (request.POST.get('verification_code') or '').strip()
            stored_code = request.session.get('login_verification_code')
            user_id = request.session.get('login_user_id')

            if not stored_code or not user_id:
                return JsonResponse({
                    'success': False,
                    'message': 'Сессия истекла. Войдите заново.'
                })

            if not code_is_fresh(request.session, 'login_verification_time'):
                _clear_session(request, LOGIN_SESSION_KEYS)
                return JsonResponse({'success': False, 'message': 'Код истёк.'})

            if bump_attempt(request.session, 'login_code_attempts') > MAX_CODE_ATTEMPTS:
                _clear_session(request, LOGIN_SESSION_KEYS)
                return JsonResponse({'success': False, 'message': 'Слишком много попыток.'})

            if not secrets.compare_digest(verification_code, stored_code):
                return JsonResponse({'success': False, 'message': 'Неверный код.'})

            user = User.objects.filter(id=user_id).first()
            if user is None:
                _clear_session(request, LOGIN_SESSION_KEYS)
                return JsonResponse({'success': False, 'message': 'Ошибка входа.'})

            _clear_session(request, LOGIN_SESSION_KEYS)
            auth_login(request, user)
            return JsonResponse({'success': True, 'redirect_url': '/home/'})

        # ---------------- RESEND SIGNUP CODE ----------------
        elif action == 'resend_signup_code':
            signup_data = request.session.get('signup_data')
            if not signup_data:
                return JsonResponse({'success': False, 'message': 'Сессия истекла.'})

            verification_code = gen_code()
            request.session['verification_code'] = verification_code
            request.session['verification_time'] = datetime.now().isoformat()
            request.session['signup_code_attempts'] = 0
            request.session.modified = True

            try:
                send_mail(
                    'Verify Your Email - CodeSport',
                    f'Your new verification code is: {verification_code}\n\n'
                    f'This code will expire in 10 minutes.',
                    settings.DEFAULT_FROM_EMAIL,
                    [signup_data['email']],
                    fail_silently=False,
                )
            except Exception:
                return JsonResponse({'success': False, 'message': 'Не удалось отправить письмо.'})

            return JsonResponse({'success': True, 'message': 'Код отправлен.'})

        # ---------------- RESEND LOGIN CODE ----------------
        elif action == 'resend_login_code':
            user_id = request.session.get('login_user_id')
            if not user_id:
                return JsonResponse({'success': False, 'message': 'Сессия истекла.'})

            user = User.objects.filter(id=user_id).first()
            if user is None:
                _clear_session(request, LOGIN_SESSION_KEYS)
                return JsonResponse({'success': False, 'message': 'Ошибка.'})

            verification_code = gen_code()
            request.session['login_verification_code'] = verification_code
            request.session['login_verification_time'] = datetime.now().isoformat()
            request.session['login_code_attempts'] = 0
            request.session.modified = True

            try:
                send_mail(
                    'Verify Your Login - CodeSport',
                    f'Your new login verification code is: {verification_code}\n\n'
                    f'This code will expire in 10 minutes.',
                    settings.DEFAULT_FROM_EMAIL,
                    [user.email],
                    fail_silently=False,
                )
            except Exception:
                return JsonResponse({'success': False, 'message': 'Не удалось отправить письмо.'})

            return JsonResponse({'success': True, 'message': 'Код отправлен.'})

        # ---------------- FORGOT PASSWORD ----------------
        elif action == 'forgot_password':
            email = (request.POST.get('email') or '').strip().lower()
            user = User.objects.filter(email__iexact=email).first()

            if user:
                reset_code = gen_code()
                request.session['reset_code'] = reset_code
                request.session['reset_email'] = email
                request.session['reset_time'] = datetime.now().isoformat()
                request.session['reset_code_attempts'] = 0
                request.session.modified = True

                try:
                    send_mail(
                        'Password Reset - CodeSport',
                        f'Your password reset code is: {reset_code}\n\n'
                        f'This code will expire in 10 minutes.',
                        settings.DEFAULT_FROM_EMAIL,
                        [email],
                        fail_silently=False,
                    )
                except Exception:
                    _clear_session(request, RESET_SESSION_KEYS)
                    # Всё равно отвечаем success — не палим существование email
                    return JsonResponse({'success': True, 'email': email})

            # Единый ответ независимо от существования аккаунта
            return JsonResponse({'success': True, 'email': email})

        # ---------------- RESET PASSWORD ----------------
        elif action == 'reset_password':
            verification_code = (request.POST.get('verification_code') or '').strip()
            email = (request.POST.get('email') or '').strip().lower()
            new_password = request.POST.get('new_password') or ''

            stored_code = request.session.get('reset_code')
            stored_email = request.session.get('reset_email')

            if not stored_code or not stored_email:
                return JsonResponse({'success': False, 'message': 'Сессия истекла.'})
            if stored_email != email:
                return JsonResponse({'success': False, 'message': 'Неверный email.'})
            if not code_is_fresh(request.session, 'reset_time'):
                _clear_session(request, RESET_SESSION_KEYS)
                return JsonResponse({'success': False, 'message': 'Код истёк.'})
            if bump_attempt(request.session, 'reset_code_attempts') > MAX_CODE_ATTEMPTS:
                _clear_session(request, RESET_SESSION_KEYS)
                return JsonResponse({'success': False, 'message': 'Слишком много попыток.'})
            if not secrets.compare_digest(verification_code, stored_code):
                return JsonResponse({'success': False, 'message': 'Неверный код.'})
            if len(new_password) < 8:
                return JsonResponse({'success': False, 'message': 'Пароль слишком короткий.'})

            user = User.objects.filter(email__iexact=email).first()
            if user is None:
                return JsonResponse({'success': False, 'message': 'Ошибка.'})

            user.set_password(new_password)
            user.save()
            _clear_session(request, RESET_SESSION_KEYS)
            return JsonResponse({'success': True, 'message': 'Пароль обновлён.'})

        # ---------------- RESEND RESET CODE ----------------
        elif action == 'resend_reset_code':
            email = (request.POST.get('email') or '').strip().lower()
            stored_email = request.session.get('reset_email')

            if not stored_email or stored_email != email:
                # Не подтверждаем существование адреса
                return JsonResponse({'success': True, 'message': 'Код отправлен.'})

            reset_code = gen_code()
            request.session['reset_code'] = reset_code
            request.session['reset_time'] = datetime.now().isoformat()
            request.session['reset_code_attempts'] = 0
            request.session.modified = True

            try:
                send_mail(
                    'Password Reset - CodeSport',
                    f'Your new password reset code is: {reset_code}\n\n'
                    f'This code will expire in 10 minutes.',
                    settings.DEFAULT_FROM_EMAIL,
                    [email],
                    fail_silently=False,
                )
            except Exception:
                return JsonResponse({'success': False, 'message': 'Не удалось отправить письмо.'})

            return JsonResponse({'success': True, 'message': 'Код отправлен.'})

    return render(request, 'start/login.html')

def home(request):
    return render(request, 'main/home.html')


def is_support_official(user):
    """Check if user is CodeSupportOfficial"""
    return user.username == 'CodeSupportOfficial'


@login_required
def admin_panel(request):
    """Admin panel view - only accessible by CodeSupportOfficial"""
    # Block access if not CodeSupportOfficial
    if not is_support_official(request.user):
        raise PermissionDenied("Access denied. Only CodeSupportOfficial can access this page.")

    total_problems = Problem.objects.count()
    total_users = User.objects.count()
    total_submissions = Submission.objects.count()

    # Additional stats for CodeSupportOfficial
    accepted_submissions = Submission.objects.filter(verdict='accepted').count()
    wrong_submissions = Submission.objects.filter(verdict='wrong_answer').count()
    active_users = User.objects.filter(is_active=True).count()

    all_problems = Problem.objects.all().order_by('-created_at')
    all_users = User.objects.all().order_by('-date_joined')
    recent_submissions = Submission.objects.all().order_by('-submitted_at')[:20]

    context = {
        'total_problems': total_problems,
        'total_users': total_users,
        'total_submissions': total_submissions,
        'accepted_submissions': accepted_submissions,
        'wrong_submissions': wrong_submissions,
        'active_users': active_users,
        'all_problems': all_problems,
        'all_users': all_users,
        'recent_submissions': recent_submissions,
        'is_support_official': True,
    }

    return render(request, 'main/admin_panel.html', context)


@login_required
@require_POST
def delete_problem(request, problem_id):
    """Delete a problem (CodeSupportOfficial only)"""
    if not is_support_official(request.user):
        return JsonResponse({'success': False, 'message': 'Access denied'}, status=403)

    try:
        problem = Problem.objects.get(id=problem_id)
        problem.delete()
        return JsonResponse({'success': True})
    except Problem.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'Problem not found'})


@login_required
@require_POST
def delete_user(request, user_id):
    """Delete a user (CodeSupportOfficial only)"""
    if not is_support_official(request.user):
        return JsonResponse({'success': False, 'message': 'Access denied'}, status=403)

    try:
        user = User.objects.get(id=user_id)
        if user.username == 'CodeSupportOfficial':
            return JsonResponse({'success': False, 'message': 'Cannot delete main admin account'})
        user.delete()
        return JsonResponse({'success': True})
    except User.DoesNotExist:
        return JsonResponse({'success': False, 'message': 'User not found'})


@login_required
@require_POST
def toggle_staff(request, user_id):
    """Toggle staff status for a user (CodeSupportOfficial only)"""
    # Check if user is CodeSupportOfficial
    if request.user.username != 'CodeSupportOfficial':
        return JsonResponse({
            'success': False,
            'message': 'Access denied. Only CodeSupportOfficial can perform this action.'
        }, status=403)

    try:
        user = User.objects.get(id=user_id)

        # Prevent modifying CodeSupportOfficial account
        if user.username == 'CodeSupportOfficial':
            return JsonResponse({
                'success': False,
                'message': 'Cannot modify CodeSupportOfficial account.'
            })

        # Toggle staff status
        user.is_staff = not user.is_staff
        user.save()


        return JsonResponse({
            'success': True,
            'message': f'Admin status {"granted" if user.is_staff else "revoked"} for {user.username}',
            'is_staff': user.is_staff
        })

    except User.DoesNotExist:
        return JsonResponse({
            'success': False,
            'message': 'User not found.'
        }, status=404)
    except Exception as e:
        return JsonResponse({
            'success': False,
            'message': f'Error: {str(e)}'
        }, status=500)


@login_required
def edit_problem(request, problem_id):
    if not is_support_official(request.user):
        raise PermissionDenied("Access denied")

    problem = get_object_or_404(Problem, id=problem_id)

    if request.method == 'POST':
        form = ProblemForm(request.POST, instance=problem)
        if form.is_valid():
            form.save()
            messages.success(request, 'Problem updated successfully!')
            return redirect('admin_panel')  # This will use the new URL name
    else:
        form = ProblemForm(instance=problem)

    return render(request, 'main/edit_problem.html', {
        'form': form,
        'problem': problem
    })


@login_required
def problems(request):
    problems_list = Problem.objects.all().order_by('-created_at')
    return render(request, 'main/problems.html', {'problems': problems_list})

@login_required
def create_problem(request):
    if request.method == 'POST':
        form = ProblemForm(request.POST)
        if form.is_valid():
            problem = form.save(commit=False)
            problem.author = request.user
            problem.save()
            
            messages.success(request, 'Problem created successfully! Now add test cases and solutions.')
            return redirect('add_test_cases', problem_id=problem.id)
    else:
        form = ProblemForm()
    return render(request, 'main/create_problem.html', {'form': form})

@login_required
def add_test_cases(request, problem_id):
    problem = get_object_or_404(Problem, id=problem_id)
    if problem.author != request.user:
        return HttpResponseForbidden("You don't have permission to add test cases to this problem.")
    
    if request.method == 'POST':
        form = TestCaseForm(request.POST)
        if form.is_valid():
            test_case = form.save(commit=False)
            test_case.problem = problem
            test_case.save()
            messages.success(request, 'Test case added successfully!')
            return redirect('add_test_cases', problem_id=problem.id)
    else:
        next_order = problem.test_cases.count()
        form = TestCaseForm(initial={'order': next_order})
    
    test_cases = TestCase.objects.filter(problem=problem)
    return render(request, 'main/add_test_cases.html', {
        'problem': problem, 
        'form': form, 
        'test_cases': test_cases
    })

@login_required
def edit_test_case(request, test_case_id):
    test_case = get_object_or_404(TestCase, id=test_case_id)
    problem = test_case.problem
    
    if problem.author != request.user:
        return HttpResponseForbidden("You don't have permission to edit this test case.")
    
    if request.method == 'POST':
        form = TestCaseForm(request.POST, instance=test_case)
        if form.is_valid():
            form.save()
            messages.success(request, 'Test case updated successfully!')
            return redirect('add_test_cases', problem_id=problem.id)
    else:
        form = TestCaseForm(instance=test_case)
    
    return render(request, 'main/edit_test_case.html', {
        'form': form,
        'test_case': test_case,
        'problem': problem
    })

@login_required
def delete_test_case(request, test_case_id):
    test_case = get_object_or_404(TestCase, id=test_case_id)
    problem = test_case.problem

    if problem.author != request.user:
        return HttpResponseForbidden("You don't have permission to delete this test case.")
    
    if request.method == 'POST':
        test_case.delete()
        messages.success(request, 'Test case deleted successfully!')
        return redirect('add_test_cases', problem_id=problem.id)
    
    return render(request, 'main/delete_test_case.html', {
        'test_case': test_case,
        'problem': problem
    })

@login_required
def add_solutions(request, problem_id):
    problem = get_object_or_404(Problem, id=problem_id)
    
    is_owner = (problem.author == request.user)
    
    if request.method == 'POST':
        if not is_owner:
            return HttpResponseForbidden("You don't have permission to add solutions to this problem.")
        
        form = SolutionForm(request.POST)
        if form.is_valid():
            solution = form.save(commit=False)
            solution.problem = problem
            solution.save()
            messages.success(request, 'Solution added successfully!')
            return redirect('add_solutions', problem_id=problem.id)
    else:
        form = SolutionForm()
    
    solutions = Solution.objects.filter(problem=problem)
    return render(request, 'main/add_solutions.html', {
        'problem': problem, 
        'form': form, 
        'solutions': solutions,
        'is_owner': is_owner
    })

@login_required
@require_POST
def delete_solution(request, solution_id):
    solution = get_object_or_404(Solution, id=solution_id)

    # Разрешаем удалять только владельцу задачи
    if solution.problem.author != request.user:
        return redirect('problem_detail', problem_id=solution.problem.id)

    problem_id = solution.problem.id
    solution.delete()
    return redirect('add_solutions', problem_id=problem_id)

@login_required
def user_problems(request):
    user_problems = Problem.objects.filter(author=request.user).order_by('-created_at')
    return render(request, 'main/user_problems.html', {'problems': user_problems})

@login_required
def problem_detail(request, problem_id):
    problem = get_object_or_404(Problem, id=problem_id)
    public_test_cases = TestCase.objects.filter(problem=problem, is_public=True)
    return render(request, 'main/problem_detail.html', {
        'problem': problem,
        'public_test_cases': public_test_cases
    })

@login_required
def submit_solution(request, problem_id):
    problem = get_object_or_404(Problem, id=problem_id)
    test_cases = TestCase.objects.filter(problem=problem)
    
    if request.method == 'POST':
        form = SubmissionForm(request.POST)
        if form.is_valid():
            submission = form.save(commit=False)
            submission.problem = problem
            submission.user = request.user
            submission.total_test_cases = test_cases.count()
            
            results = run_code(submission.code, submission.language, test_cases)
            submission.test_cases_passed = results['passed']
            
            if results['passed'] == test_cases.count():
                submission.verdict = 'accepted'
                messages.success(request, 'Congratulations! All test cases passed.')
            else:
                submission.verdict = 'wrong_answer'
                messages.warning(request, f'{results["passed"]} out of {test_cases.count()} test cases passed.')
            
            submission.save()
            return redirect('submission_result', submission_id=submission.id)
    else:
        initial_code = problem.template_code if problem.template_code else ''
        form = SubmissionForm(initial={'code': initial_code, 'language': 'python'})
    
    return render(request, 'main/submit_solution.html', {
        'problem': problem, 
        'form': form,
        'test_cases_count': test_cases.count()
    })

@login_required
def submission_result(request, submission_id):
    submission = get_object_or_404(Submission, id=submission_id, user=request.user)
    return render(request, 'main/submission_result.html', {'submission': submission})

def run_code(code, language, test_cases, timeout=5, compile_timeout=15):
    test_cases = list(test_cases)
    results = {'passed': 0, 'details': []}

    lang = (language or '').lower()
    if lang in ('c++', 'cpp'):
        lang = 'cpp'
    elif lang in ('js', 'javascript'):
        lang = 'javascript'

    def add_detail(tc, status, output, expected=None):
        if expected is None:
            expected = _as_text(tc.expected_output).strip()
        results['details'].append({
            'test_case': tc.order,
            'status': status,
            'output': output,
            'expected': expected,
        })

    def mark_compile_error(message):
        logger.error("Compile error:\n%s", message)
        for tc in test_cases:
            add_detail(tc, 'compile_error', message)

    def run_test(cmd, tc, workdir, limits):
        expected = _as_text(tc.expected_output).strip()
        input_data = _as_text(tc.input)

        res = run_sandboxed(
            cmd, input_data, timeout, workdir,
            mem_mb=limits['mem_mb'],
            fsize_mb=limits['fsize_mb'],
            nproc=limits['nproc'],
        )

        if res.error:
            add_detail(tc, 'error', f'Runtime Error: {res.error}', expected)
            return
        if res.timed_out:
            add_detail(tc, 'timeout', 'Time Limit Exceeded', expected)
            return

        output, stderr = res.stdout, res.stderr

        if res.returncode != 0:
            if res.returncode < 0:
                # Убит сигналом — обычно это RLIMIT_AS / RLIMIT_CPU
                sig = -res.returncode
                try:
                    name = _signal.Signals(sig).name
                except ValueError:
                    name = f'signal {sig}'
                if name in ('SIGKILL', 'SIGSEGV', 'SIGABRT'):
                    msg = f'Memory Limit Exceeded / killed ({name})'
                elif name == 'SIGXCPU':
                    msg = 'Time Limit Exceeded (CPU)'
                else:
                    msg = f'Killed by {name}'
                add_detail(tc, 'error', msg, expected)
            else:
                err = stderr or output or f'Exit code {res.returncode}'
                add_detail(tc, 'error', err, expected)
        elif output == expected:
            results['passed'] += 1
            add_detail(tc, 'passed', output, expected)
        else:
            add_detail(tc, 'failed', output, expected)

    def run_interpreted(suffix, cmd_prefix, limits):
        with tempfile.TemporaryDirectory(prefix='judge_') as temp_dir:
            src = os.path.join(temp_dir, f'solution{suffix}')
            with open(src, 'w', encoding='utf-8') as f:
                f.write(code)
            os.chmod(src, 0o644)

            for tc in test_cases:
                run_test([*cmd_prefix, src], tc, temp_dir, limits)

    # ---------------- Python ----------------
    if lang == 'python':
        run_interpreted('.py', [sys.executable], DEFAULT_LIMITS)

    # ---------------- JavaScript ----------------
    elif lang == 'javascript':
        run_interpreted('.js', ['node'], DEFAULT_LIMITS)

    # ---------------- C++ ----------------
    elif lang == 'cpp':
        base_dir = os.environ.get('JUDGE_TMP') or os.path.join(
            tempfile.gettempdir(), 'judge'
        )
        os.makedirs(base_dir, exist_ok=True)
        os.chmod(base_dir, 0o700)

        with tempfile.TemporaryDirectory(dir=base_dir, prefix='judge_') as temp_dir:
            src = os.path.join(temp_dir, 'solution.cpp')
            exe = os.path.join(temp_dir, 'solution')

            with open(src, 'w', encoding='utf-8') as f:
                f.write(code)
            os.chmod(src, 0o644)

            # ---- Компиляция в песочнице ----
            res = run_sandboxed(
                ['g++', '-std=c++17', '-O2', '-pipe',
                 '-fno-asm',           # опционально: чуть меньше «магии»
                 src, '-o', exe],
                '', compile_timeout, temp_dir,
                mem_mb=COMPILE_LIMITS['mem_mb'],
                fsize_mb=COMPILE_LIMITS['fsize_mb'],
                nproc=COMPILE_LIMITS['nproc'],
                env={'PATH': '/usr/bin:/bin'},
            )
            if res.error:
                mark_compile_error(res.error)
                return results
            if res.timed_out:
                mark_compile_error('Compilation Time Limit Exceeded')
                return results
            if res.returncode != 0:
                msg = (res.stderr or res.stdout or 'Compilation failed').strip()
                mark_compile_error(msg)
                return results

            if os.name != 'nt':
                os.chmod(exe, 0o755)

            for tc in test_cases:
                run_test([exe], tc, temp_dir, DEFAULT_LIMITS)

    # ---------------- Java ----------------
    elif lang == 'java':
        with tempfile.TemporaryDirectory(prefix='judge_') as temp_dir:
            match = (
                re.search(r'public\s+(?:final\s+|abstract\s+)?class\s+(\w+)', code)
                or re.search(r'class\s+(\w+)', code)
            )
            class_name = match.group(1) if match else 'Main'
            src = os.path.join(temp_dir, f'{class_name}.java')

            with open(src, 'w', encoding='utf-8') as f:
                f.write(code)

            res = run_sandboxed(
                ['javac', f'{class_name}.java'],
                '', compile_timeout, temp_dir,
                mem_mb=COMPILE_LIMITS['mem_mb'],
                fsize_mb=COMPILE_LIMITS['fsize_mb'],
                nproc=COMPILE_LIMITS['nproc'],
                env={'PATH': '/usr/bin:/bin'},
            )
            if res.error:
                mark_compile_error(res.error)
                return results
            if res.timed_out:
                mark_compile_error('Compilation Time Limit Exceeded')
                return results
            if res.returncode != 0:
                msg = (res.stderr or res.stdout or 'Compilation failed').strip()
                mark_compile_error(msg)
                return results

            for tc in test_cases:
                run_test(
                    ['java',
                     '-Djava.io.tmpdir=' + temp_dir,   # JVM пишет только сюда
                     '-XX:+UseSerialGC',               # меньше потоков
                     '-Xshare:auto',
                     '-cp', temp_dir, class_name],
                    tc, temp_dir, JAVA_LIMITS,
                )

    else:
        raise ValueError(f'Unsupported language: {language}')

    return results

def contests(request):
    return HttpResponse('<h2>WillBeRedacted</h2>')

def leaderboard(request):
    return HttpResponse('<h2>WillBeRedacted</h2>')

def about(request):
    return HttpResponse('<h2>WillBeRedacted</h2>')


@login_required
def profile(request, username=None):
    # If no username is provided, show the current user's profile
    if username:
        profile_user = get_object_or_404(User, username=username)
    else:
        profile_user = request.user

    # Get user's submissions
    user_submissions = Submission.objects.filter(user=profile_user).order_by('-submitted_at')

    # Calculate statistics
    total_submissions = user_submissions.count()
    accepted_submissions = user_submissions.filter(verdict='accepted').count()

    # Get unique problems solved
    problems_solved = user_submissions.filter(verdict='accepted').values('problem').distinct().count()

    # Calculate acceptance rate
    acceptance_rate = 0
    if total_submissions > 0:
        acceptance_rate = round((accepted_submissions / total_submissions) * 100, 1)

    # Get recent submissions (last 10)
    recent_submissions = user_submissions[:10]

    # Get problems created by this user
    created_problems = Problem.objects.filter(author=profile_user).order_by('-created_at')[:5]

    # Define achievements based on stats
    achievements = []
    if accepted_submissions >= 1:
        achievements.append({'icon': '✅', 'name': 'First Accepted'})
    if accepted_submissions >= 10:
        achievements.append({'icon': '🏆', 'name': '10 Accepted'})
    if accepted_submissions >= 50:
        achievements.append({'icon': '👑', 'name': '50 Accepted'})
    if problems_solved >= 5:
        achievements.append({'icon': '🎯', 'name': '5 Problems Solved'})
    if problems_solved >= 20:
        achievements.append({'icon': '🚀', 'name': '20 Problems Solved'})
    if total_submissions >= 100:
        achievements.append({'icon': '💪', 'name': '100 Submissions'})

    context = {
        'profile_user': profile_user,
        'total_submissions': total_submissions,
        'accepted_submissions': accepted_submissions,
        'problems_solved': problems_solved,
        'acceptance_rate': acceptance_rate,
        'recent_submissions': recent_submissions,
        'created_problems': created_problems,
        'achievements': achievements,
    }


    return render(request, 'main/profile.html', context)


@login_required
def submissions(request):
    # Get all submissions
    submissions_list = Submission.objects.all().order_by('-submitted_at')

    # Check if user wants to see all submissions or just their own
    show_all = request.GET.get('show_all', 'false').lower() == 'true'

    # By default, show only the current user's submissions
    if not show_all and not request.user.is_staff:
        submissions_list = submissions_list.filter(user=request.user)

    # Get filter parameters from GET request
    search_query = request.GET.get('search', '')
    problem_id = request.GET.get('problem_id', '')
    username = request.GET.get('user', '')
    verdict = request.GET.get('verdict', '')
    language = request.GET.get('language', '')

    # Apply filters
    if search_query:
        submissions_list = submissions_list.filter(problem__title__icontains=search_query)

    if problem_id:
        try:
            problem_id_int = int(problem_id)
            submissions_list = submissions_list.filter(problem__id=problem_id_int)
        except ValueError:
            pass

    if username:
        submissions_list = submissions_list.filter(user__username__icontains=username)

    if verdict:
        submissions_list = submissions_list.filter(verdict=verdict)

    if language:
        submissions_list = submissions_list.filter(language=language)

    return render(request, 'main/submissions.html', {
        'submissions': submissions_list,
        'show_all': show_all
    })

@login_required
def logout(request):
    if request.method == 'POST':
        auth_logout(request)
        messages.success(request, 'You have been successfully logged out.')
        return redirect('login')
    
    return render(request, 'main/logout.html')
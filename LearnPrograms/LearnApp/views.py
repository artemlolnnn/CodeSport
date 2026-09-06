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

from .models import *
from .forms import *
import subprocess
import tempfile
import os
import random
import json
from datetime import datetime, timedelta


def login_view(request):
    if request.user.is_authenticated:
        return redirect('home')

    if request.method == "POST":
        action = request.POST.get('action')

        if action == 'login':
            username = request.POST.get('username')
            password = request.POST.get('password')

            # Check if user entered email
            if '@' in username:
                try:
                    user_obj = User.objects.get(email=username)
                    username = user_obj.username
                except User.DoesNotExist:
                    return JsonResponse({
                        'success': False,
                        'message': 'No account found with this email.'
                    })

            user = authenticate(request, username=username, password=password)

            if user is not None:
                # Generate verification code for login
                verification_code = str(random.randint(100000, 999999))

                # Store in session
                request.session['login_verification_code'] = verification_code
                request.session['login_username'] = username
                request.session['login_password'] = password
                request.session['login_verification_time'] = datetime.now().isoformat()
                request.session.modified = True

                # Send verification email
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

                    return JsonResponse({
                        'requires_verification': True,
                        'username': username,
                        'password': password,
                        'email': user.email
                    })

                except Exception as e:
                    # Clean up session
                    request.session.pop('login_verification_code', None)
                    request.session.pop('login_username', None)
                    request.session.pop('login_password', None)
                    request.session.pop('login_verification_time', None)
                    request.session.modified = True

                    return JsonResponse({
                        'success': False,
                        'message': f'Failed to send verification email: {str(e)}'
                    })
            else:
                return JsonResponse({
                    'success': False,
                    'message': 'Invalid username/email or password.'
                })

        elif action == 'signup':
            username = request.POST.get('username')
            email = request.POST.get('email')
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')

            if password != confirm_password:
                return JsonResponse({
                    'success': False,
                    'message': 'Passwords do not match.'
                })

            if User.objects.filter(username=username).exists():
                return JsonResponse({
                    'success': False,
                    'message': 'Username already exists.'
                })

            if User.objects.filter(email=email).exists():
                return JsonResponse({
                    'success': False,
                    'message': 'Email already registered.'
                })

            # Generate verification code
            verification_code = str(random.randint(100000, 999999))

            # Store in session
            request.session['verification_code'] = verification_code
            request.session['signup_data'] = {
                'username': username,
                'email': email,
                'password': password
            }
            request.session['verification_time'] = datetime.now().isoformat()
            request.session.modified = True

            # Send verification email
            try:
                send_mail(
                    'Verify Your Email - CodeSport',
                    f'Your verification code is: {verification_code}\n\n'
                    f'This code will expire in 10 minutes.',
                    settings.DEFAULT_FROM_EMAIL,
                    [email],
                    fail_silently=False,
                )

                return JsonResponse({
                    'success': True,
                    'email': email,
                    'username': username,
                    'password': password
                })

            except Exception as e:
                # Clean up session
                request.session.pop('verification_code', None)
                request.session.pop('signup_data', None)
                request.session.pop('verification_time', None)
                request.session.modified = True

                return JsonResponse({
                    'success': False,
                    'message': f'Failed to send verification email: {str(e)}'
                })

        elif action == 'verify_signup':
            verification_code = request.POST.get('verification_code')
            email = request.POST.get('email')
            username = request.POST.get('username')
            password = request.POST.get('password')

            stored_code = request.session.get('verification_code')
            signup_data = request.session.get('signup_data')

            if not stored_code or not signup_data:
                return JsonResponse({
                    'success': False,
                    'message': 'No verification session found. Please sign up again.'
                })

            if verification_code == stored_code:
                # Create user
                try:
                    user = User.objects.create_user(
                        username=signup_data['username'],
                        email=signup_data['email'],
                        password=signup_data['password']
                    )
                    user.save()

                    # Clean up session
                    request.session.pop('verification_code', None)
                    request.session.pop('signup_data', None)
                    request.session.pop('verification_time', None)
                    request.session.modified = True

                    # Auto-login the user
                    user = authenticate(
                        request,
                        username=signup_data['username'],
                        password=signup_data['password']
                    )
                    if user:
                        auth_login(request, user)
                        return JsonResponse({
                            'success': True,
                            'redirect_url': '/home/'
                        })

                except Exception as e:
                    return JsonResponse({
                        'success': False,
                        'message': f'Failed to create account: {str(e)}'
                    })
            else:
                return JsonResponse({
                    'success': False,
                    'message': 'Invalid verification code.'
                })

        elif action == 'verify_login':
            verification_code = request.POST.get('verification_code')
            username = request.POST.get('username')
            password = request.POST.get('password')

            stored_code = request.session.get('login_verification_code')
            stored_username = request.session.get('login_username')
            stored_password = request.session.get('login_password')

            if not stored_code or not stored_username:
                return JsonResponse({
                    'success': False,
                    'message': 'No login verification session found. Please login again.'
                })

            if verification_code == stored_code and stored_username == username:
                user = authenticate(request, username=username, password=stored_password)

                if user is not None:
                    # Clean up session
                    request.session.pop('login_verification_code', None)
                    request.session.pop('login_username', None)
                    request.session.pop('login_password', None)
                    request.session.pop('login_verification_time', None)
                    request.session.modified = True

                    auth_login(request, user)
                    return JsonResponse({
                        'success': True,
                        'redirect_url': '/home/'
                    })
                else:
                    return JsonResponse({
                        'success': False,
                        'message': 'Authentication failed. Please try again.'
                    })
            else:
                return JsonResponse({
                    'success': False,
                    'message': 'Invalid verification code.'
                })

        elif action == 'resend_signup_code':
            email = request.POST.get('email')

            if email:
                verification_code = str(random.randint(100000, 999999))
                request.session['verification_code'] = verification_code
                request.session['verification_time'] = datetime.now().isoformat()
                request.session.modified = True

                try:
                    send_mail(
                        'Verify Your Email - CodeSport',
                        f'Your new verification code is: {verification_code}\n\n'
                        f'This code will expire in 10 minutes.',
                        settings.DEFAULT_FROM_EMAIL,
                        [email],
                        fail_silently=False,
                    )
                    return JsonResponse({'success': True, 'message': 'Code sent successfully'})
                except Exception as e:
                    return JsonResponse({'success': False, 'message': str(e)})

            return JsonResponse({'success': False, 'message': 'Email is required'})

        elif action == 'resend_login_code':
            username = request.POST.get('username')

            if username:
                try:
                    user = User.objects.get(username=username)
                    verification_code = str(random.randint(100000, 999999))
                    request.session['login_verification_code'] = verification_code
                    request.session['login_verification_time'] = datetime.now().isoformat()
                    request.session.modified = True

                    send_mail(
                        'Verify Your Login - CodeSport',
                        f'Your new login verification code is: {verification_code}\n\n'
                        f'This code will expire in 10 minutes.',
                        settings.DEFAULT_FROM_EMAIL,
                        [user.email],
                        fail_silently=False,
                    )
                    return JsonResponse({'success': True, 'message': 'Code sent successfully'})
                except User.DoesNotExist:
                    return JsonResponse({'success': False, 'message': 'User not found'})
                except Exception as e:
                    return JsonResponse({'success': False, 'message': str(e)})

            return JsonResponse({'success': False, 'message': 'Username is required'})

        elif action == 'forgot_password':
            email = request.POST.get('email')

            try:
                user = User.objects.get(email=email)

                # Generate reset code
                reset_code = str(random.randint(100000, 999999))

                # Store in session
                request.session['reset_code'] = reset_code
                request.session['reset_email'] = email
                request.session['reset_time'] = datetime.now().isoformat()
                request.session.modified = True

                # Send reset email
                send_mail(
                    'Password Reset - CodeSport',
                    f'Your password reset code is: {reset_code}\n\n'
                    f'This code will expire in 10 minutes.\n\n'
                    f'If you did not request this, please ignore this email.',
                    settings.DEFAULT_FROM_EMAIL,
                    [email],
                    fail_silently=False,
                )

                return JsonResponse({
                    'success': True,
                    'email': email
                })

            except User.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'message': 'No account found with this email.'
                })
            except Exception as e:
                return JsonResponse({
                    'success': False,
                    'message': f'Failed to send email: {str(e)}'
                })

        elif action == 'reset_password':
            verification_code = request.POST.get('verification_code')
            email = request.POST.get('email')
            new_password = request.POST.get('new_password')

            stored_code = request.session.get('reset_code')
            stored_email = request.session.get('reset_email')

            if not stored_code or not stored_email:
                return JsonResponse({
                    'success': False,
                    'message': 'Reset session expired. Please try again.'
                })

            if stored_email != email:
                return JsonResponse({
                    'success': False,
                    'message': 'Email mismatch.'
                })

            if verification_code != stored_code:
                return JsonResponse({
                    'success': False,
                    'message': 'Invalid reset code.'
                })

            try:
                user = User.objects.get(email=email)
                user.set_password(new_password)
                user.save()

                # Clean up session
                request.session.pop('reset_code', None)
                request.session.pop('reset_email', None)
                request.session.pop('reset_time', None)
                request.session.modified = True

                return JsonResponse({
                    'success': True,
                    'message': 'Password reset successfully!'
                })

            except User.DoesNotExist:
                return JsonResponse({
                    'success': False,
                    'message': 'User not found.'
                })
            except Exception as e:
                return JsonResponse({
                    'success': False,
                    'message': f'Error: {str(e)}'
                })

        elif action == 'resend_reset_code':
            email = request.POST.get('email')

            if email:
                reset_code = str(random.randint(100000, 999999))
                request.session['reset_code'] = reset_code
                request.session['reset_time'] = datetime.now().isoformat()
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
                    return JsonResponse({'success': True, 'message': 'Code sent successfully'})
                except Exception as e:
                    return JsonResponse({'success': False, 'message': str(e)})

            return JsonResponse({'success': False, 'message': 'Email is required'})

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

def run_code(code, language, test_cases):
    results = {'passed': 0, 'details': []}
    
    if language == 'python':
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write(code)
            temp_file = f.name
        
        try:
            for test_case in test_cases:
                process = subprocess.run(
                    ['python', temp_file],
                    input=test_case.input,
                    text=True,
                    capture_output=True,
                    timeout=1
                )
                
                output = process.stdout.strip()
                expected = test_case.expected_output.strip()
                
                if output == expected:
                    results['passed'] += 1
                    results['details'].append({
                        'test_case': test_case.order,
                        'status': 'passed',
                        'output': output,
                        'expected': expected
                    })
                else:
                    results['details'].append({
                        'test_case': test_case.order,
                        'status': 'failed',
                        'output': output,
                        'expected': expected
                    })
                
        except subprocess.TimeoutExpired:
            results['details'].append({
                'test_case': test_case.order,
                'status': 'timeout',
                'output': 'Time Limit Exceeded',
                'expected': test_case.expected_output.strip()
            })
        except Exception as e:
            results['details'].append({
                'test_case': test_case.order,
                'status': 'error',
                'output': f'Runtime Error: {str(e)}',
                'expected': test_case.expected_output.strip()
            })
        finally:
            os.unlink(temp_file)
    
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
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.models import User
from django.contrib import messages
from django.http import *
from django.contrib.auth.decorators import login_required
from .models import *
from .forms import *
import subprocess
import tempfile
import os

def login_view(request):
    if request.user.is_authenticated:
        return redirect('home')
    
    if request.method == "POST":
        action = request.POST.get('action')
        
        if action == 'login':
            username = request.POST.get('username')
            password = request.POST.get('password')
            user = authenticate(request, username=username, password=password)
            
            if user is not None:
                auth_login(request, user)
                return redirect('home')
            else:
                messages.error(request, 'Invalid username or password.')
                
        elif action == 'signup':
            username = request.POST.get('username')
            email = request.POST.get('email')
            password = request.POST.get('password')
            confirm_password = request.POST.get('confirm_password')
            
            if password == confirm_password:
                if User.objects.filter(username=username).exists():
                    messages.error(request, 'Username already exists.')
                else:
                    user = User.objects.create_user(username=username, email=email, password=password)
                    user.save()
                    messages.success(request, 'Account created successfully. You can now login.')
            else:
                messages.error(request, 'Passwords do not match.')
    
    return render(request, 'start/login.html')

def home(request):
    return render(request, 'main/home.html')

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
                    timeout=5
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

def profile(request):
    return HttpResponse('<h2>WillBeRedacted</h2>')

def submissions(request):
    submissions_list = Submission.objects.filter(user=request.user).order_by('-submitted_at')
    return render(request, 'main/submissions.html', {'submissions': submissions_list})

@login_required
def logout(request):
    if request.method == 'POST':
        auth_logout(request)
        messages.success(request, 'You have been successfully logged out.')
        return redirect('login')
    
    return render(request, 'main/logout.html')
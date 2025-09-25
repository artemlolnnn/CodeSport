from django.db import models
from django.contrib.auth.models import User

class Problem(models.Model):
    DIFFICULTY_CHOICES = [
        ('easy', 'Easy'),
        ('medium', 'Medium'),
        ('hard', 'Hard'),
    ]
    
    title = models.CharField(max_length=200)
    description = models.TextField()
    author = models.ForeignKey(User, on_delete=models.CASCADE)
    created_at = models.DateTimeField(auto_now_add=True)
    difficulty = models.CharField(max_length=10, choices=DIFFICULTY_CHOICES)
    time_limit = models.IntegerField(default=1, help_text="Time limit in seconds")
    memory_limit = models.IntegerField(default=256, help_text="Memory limit in MB")
    template_code = models.TextField(blank=True, help_text="Initial code template for users")
    
    def __str__(self):
        return self.title
    
    def accepted_submissions(self):
        return self.submission_set.filter(verdict='accepted')
    
    def is_owner(self, user):
        return self.author == user
    
    def public_test_cases(self):
        return self.test_cases.filter(is_public=True)
    
    def test_cases_count(self):
        return self.test_cases.count()

class TestCase(models.Model):
    problem = models.ForeignKey(Problem, on_delete=models.CASCADE, related_name='test_cases')
    input = models.TextField(help_text="Input data for the test case")
    expected_output = models.TextField(help_text="Expected output for the test case")
    is_public = models.BooleanField(default=False, help_text="Whether the test case is shown to users")
    order = models.IntegerField(default=0, help_text="Order of test case execution")
    description = models.CharField(max_length=200, blank=True, help_text="Brief description of the test case")
    
    class Meta:
        ordering = ['order']
    
    def __str__(self):
        if self.description:
            return f"Test case: {self.description}"
        return f"Test case {self.order} for {self.problem.title}"

class Submission(models.Model):
    VERDICT_CHOICES = [
        ('accepted', 'Accepted'),
        ('wrong_answer', 'Wrong Answer'),
        ('time_limit_exceeded', 'Time Limit Exceeded'),
        ('runtime_error', 'Runtime Error'),
        ('compilation_error', 'Compilation Error'),
    ]
    
    LANGUAGE_CHOICES = [
        ('python', 'Python'),
        ('cpp', 'C++'),
        ('java', 'Java'),
        ('javascript', 'JavaScript'),
    ]
    
    problem = models.ForeignKey(Problem, on_delete=models.CASCADE)
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    code = models.TextField()
    language = models.CharField(max_length=20, choices=LANGUAGE_CHOICES)
    verdict = models.CharField(max_length=20, choices=VERDICT_CHOICES, blank=True)
    submitted_at = models.DateTimeField(auto_now_add=True)
    execution_time = models.FloatField(null=True, blank=True)
    test_cases_passed = models.IntegerField(default=0)
    total_test_cases = models.IntegerField(default=0)
    
    def __str__(self):
        return f"{self.user.username} - {self.problem.title}"
    
    def calculate_score(self):
        if self.total_test_cases > 0:
            return (self.test_cases_passed / self.total_test_cases) * 100
        return 0
    
    class Meta:
        ordering = ['-submitted_at']

class Solution(models.Model):
    problem = models.ForeignKey(Problem, on_delete=models.CASCADE, related_name='solutions')
    code = models.TextField(help_text="Correct solution code")
    language = models.CharField(max_length=20, choices=Submission.LANGUAGE_CHOICES)
    is_public = models.BooleanField(default=False, help_text="Whether the solution is shown to users")
    
    def __str__(self):
        return f"Solution for {self.problem.title} in {self.language}"
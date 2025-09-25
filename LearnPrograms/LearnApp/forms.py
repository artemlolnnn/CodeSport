# forms.py
from django import forms
from .models import Problem, Submission, TestCase, Solution

class ProblemForm(forms.ModelForm):
    class Meta:
        model = Problem
        fields = ['title', 'description', 'difficulty', 'time_limit', 'memory_limit', 'template_code']
        widgets = {
            'description': forms.Textarea(attrs={'rows': 10, 'class': 'form-control'}),
            'title': forms.TextInput(attrs={'class': 'form-control'}),
            'difficulty': forms.Select(attrs={'class': 'form-control'}),
            'time_limit': forms.NumberInput(attrs={'class': 'form-control'}),
            'memory_limit': forms.NumberInput(attrs={'class': 'form-control'}),
            'template_code': forms.Textarea(attrs={'rows': 10, 'class': 'form-control code-editor'}),
        }

class TestCaseForm(forms.ModelForm):
    class Meta:
        model = TestCase
        fields = ['description', 'input', 'expected_output', 'is_public', 'order']
        widgets = {
            'description': forms.TextInput(attrs={'class': 'form-control', 'placeholder': 'e.g., Simple case, Edge case, Large input'}),
            'input': forms.Textarea(attrs={'rows': 3, 'class': 'form-control font-monospace', 'placeholder': 'Enter test input...'}),
            'expected_output': forms.Textarea(attrs={'rows': 3, 'class': 'form-control font-monospace', 'placeholder': 'Enter expected output...'}),
            'is_public': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
            'order': forms.NumberInput(attrs={'class': 'form-control', 'min': 0}),
        }
        labels = {
            'is_public': 'Make this test case visible to users',
        }

class SolutionForm(forms.ModelForm):
    class Meta:
        model = Solution
        fields = ['code', 'language', 'is_public']
        widgets = {
            'code': forms.Textarea(attrs={'rows': 10, 'class': 'form-control code-editor'}),
            'language': forms.Select(attrs={'class': 'form-control'}),
            'is_public': forms.CheckboxInput(attrs={'class': 'form-check-input'}),
        }

class SubmissionForm(forms.ModelForm):
    class Meta:
        model = Submission
        fields = ['code', 'language']
        widgets = {
            'code': forms.Textarea(attrs={'rows': 15, 'class': 'form-control code-editor'}),
            'language': forms.Select(attrs={'class': 'form-control'}),
        }
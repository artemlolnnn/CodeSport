from django import template

register = template.Library()


@register.filter
def prism_lang(value):
    """Нормализует название языка под Prism.js."""
    v = (value or '').lower()
    mapping = {
        'c++': 'cpp',
        'cpp': 'cpp',
        'js': 'javascript',
        'javascript': 'javascript',
        'py': 'python',
        'python': 'python',
        'java': 'java',
    }
    return mapping.get(v, 'plaintext')
import os
import sys
sys.path.insert(0, os.path.abspath('../../'))  # Adjust path to the root of your project


# Sphinx Configuration
project = 'Udp_secure_chat'
copyright = '2025, Burak Yilmaz'
author = 'Burak Yilmaz'
release = '1.0.0'

extensions = [
    'sphinx.ext.autodoc',
    'sphinx.ext.napoleon',
]

templates_path = ['_templates']
exclude_patterns = []
html_theme = 'alabaster'
html_static_path = ['_static']

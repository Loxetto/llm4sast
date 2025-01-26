# Verifica se la libreria 'requests' è installata
try:
    import requests
    result = "requests is installed"
except ImportError:
    result = "requests is not installed"

result

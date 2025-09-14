def test_error_page(client):
    response = client.get('/nonexistent')
    assert response.status_code == 404
    assert b'page you requested could not be found' in response.data

def test_https_redirect(client):
    # Only works if FORCE_HTTPS is True and app runs with SSL
    response = client.get('/', base_url='http://localhost')
    assert response.status_code in (301, 302)
    assert 'https://' in response.headers.get('Location', '')

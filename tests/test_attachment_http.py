
def _authenticated_url_open(self, url, data=None, files=None):
    """Open an HTTP route using the exact authenticated test session.

    HttpCase.authenticate() updates the opener cookie jar. Remove any
    existing session_id cookies before explicitly supplying the current
    session ID to prevent stale or duplicate session cookies.

    Redirects are disabled so that a login or website page cannot
    masquerade as the response from the route under test.
    """
    for cookie in list(self.opener.cookies):
        if cookie.name == "session_id":
            self.opener.cookies.clear(
                cookie.domain,
                cookie.path,
                cookie.name,
            )

    headers = {
        "Cookie": (
            "session_id=%s; test_request_key=%s"
            % (self.session.sid, self.http_request_key)
        ),
    }

    response = self.url_open(
        url,
        data=data,
        files=files,
        headers=headers,
        allow_redirects=False,
    )

    self.assertEqual(
        response.history,
        [],
        "The HTTP test unexpectedly followed a redirect: %s -> %s"
        % (url, response.url),
    )

    self.assertEqual(
        response.url.split("?", 1)[0],
        self.base_url() + url.split("?", 1)[0],
        "The request did not reach the requested Odoo route. "
        "status=%s location=%s body=%s"
        % (
            response.status_code,
            response.headers.get("Location"),
            (
                response.text[:1000]
                if response.headers.get("Content-Type", "").startswith("text/")
                else ""
            ),
        ),
    )

    return response

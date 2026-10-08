from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse, JSONResponse

app = FastAPI(title="Intentionally Vulnerable Lab Target")

@app.get("/", response_class=HTMLResponse)
def index():
    return """
    <html>
        <head><title>Test Target Lab</title></head>
        <body>
            <h1>Test Application</h1>
            <a href="/products?id=1">View Product</a>
            <a href="/search?q=test">Search Items</a>
            <form action="/login" method="POST">
                <input type="text" name="username" />
                <input type="password" name="password" />
                <input type="submit" value="Login" />
            </form>
        </body>
    </html>
    """

@app.get("/products", response_class=HTMLResponse)
def products(id: str = "1"):
    # Intentionally trigger SQL error signature on quote
    if "'" in id or '"' in id:
        return HTMLResponse(
            content="500 Internal Error: You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version",
            status_code=500
        )
    return HTMLResponse(content=f"<div>Product ID: {id} - Price: $49.99</div>", status_code=200)

@app.get("/search", response_class=HTMLResponse)
def search(q: str = ""):
    # Reflects payload without escaping
    return HTMLResponse(content=f"<div>Search Results for: {q}</div>", status_code=200)

@app.get("/account", response_class=HTMLResponse)
def account_form():
    # State-changing form missing anti-csrf token
    return HTMLResponse(
        content="""
        <form action="/account/update" method="POST">
            <input type="email" name="email" value="user@example.com" />
            <input type="submit" value="Update Email" />
        </form>
        """,
        status_code=200
    )

@app.get("/fetch")
def fetch_proxy(url: str = "", redirect: str = ""):
    target = url or redirect
    if "127.0.0.1" in target or "localhost" in target:
        return Response(content="Response from localhost:8080 internal admin dashboard", status_code=200)
    elif "169.254.169.254" in target:
        return Response(content="ami-id: ami-0123456789\ninstance-id: i-0987654321", status_code=200)
    return Response(content="Proxy fetched successfully", status_code=200)

@app.get("/openapi.json")
def get_spec():
    return {
        "openapi": "3.0.0",
        "info": {"title": "Lab API", "version": "1.0"},
        "paths": {
            "/api/admin/credentials": {
                "get": {
                    "summary": "Admin Endpoint",
                    "responses": {
                        "200": {
                            "description": "OK",
                            "content": {
                                "application/json": {
                                    "schema": {
                                        "type": "object",
                                        "properties": {
                                            "username": {"type": "string"},
                                            "password": {"type": "string"},
                                            "api_key": {"type": "string"}
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
        }
    }

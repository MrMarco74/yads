from fastapi import FastAPI, Response, Form
from fastapi.responses import HTMLResponse

app = FastAPI()

@app.get("/", response_class=HTMLResponse)
async def root():
    return Response(status_code=302, headers={"Location": "/login"})

@app.get("/login", response_class=HTMLResponse)
async def login():
    return """
    <html>
        <body>
            <form action="/login" method="post">
                <input name="username">
                <input name="password">
                <button type="submit">Submit</button>
            </form>
        </body>
    </html>
    """

@app.post("/login")
async def login_post(username: str = Form(...), password: str = Form(...)):
    if username == "admin" and password == "admin":
        return Response(status_code=302, headers={"Location": "/dashboard"})
    else:
        return Response(status_code=302, headers={"Location": "/login?error=1"})

@app.get("/dashboard", response_class=HTMLResponse)
async def dashboard():
    return """
    <html>
        <body>
            <aside>
                <a href="/workers">Workers</a>
                <a href="/settings">Settings</a>
            </aside>
            <h1>Dashboard</h1>
        </body>
    </html>
    """

@app.get("/workers", response_class=HTMLResponse)
async def workers():
    return "<html><body><h1>Workers</h1></body></html>"

@app.get("/settings", response_class=HTMLResponse)
async def settings():
    return "<html><body><h1>Settings</h1></body></html>"

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="127.0.0.1", port=8015)

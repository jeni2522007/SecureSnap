
import os
from flask import Flask, render_template, send_from_directory
from routes.upload_routes import upload_bp

app = Flask(
    __name__,
    template_folder="../frontend/templates",
    static_folder="../frontend/static"
)

BASE_FOLDER = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..")
)

app.config["UPLOAD_FOLDER"] = os.path.join(BASE_FOLDER, "uploads")
app.config["PROCESSED_FOLDER"] = os.path.join(BASE_FOLDER, "processed")

app.config["MAX_CONTENT_LENGTH"] = 5 * 1024 * 1024

app.register_blueprint(upload_bp)


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/health")
def health():
    return {
        "status": "success",
        "message": "SecureSnap API is running!"
    }


@app.route("/processed/<path:filename>")
def get_processed_image(filename):
    return send_from_directory(
        app.config["PROCESSED_FOLDER"],
        filename
    )


@app.errorhandler(413)
def file_too_large(error):
    return {
        "error": "File is too large. Maximum size is 5 MB."
    }, 413


if __name__ == "__main__":
    app.run(debug=True, port=5000)

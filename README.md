🛒 E-Commerce Platform

A full-featured e-commerce platform where users can browse and purchase products across categories such as electronics, clothing, and accessories. Includes secure authentication, product management, shopping cart functions, and checkout processing.

🚀 Features

User registration & login (JWT-based)

Browse, search, and filter products

Product categories (electronics, clothing, etc.)

Product details with pricing and stock

Add to cart, update quantity, remove items

Checkout and order confirmation

Admin panel for:

Adding, editing, deleting products

Viewing all orders

SQLite database (easily replaceable with MySQL/PostgreSQL)

🛠 Tech Stack

Backend: Python, Flask, SQLAlchemy

Authentication: JWT

Database: SQLite (default)

Tools: Werkzeug, PyJWT

📦 Installation
1. Clone the repository
git clone https://github.com/your-username/ecommerce-platform.git
cd ecommerce-platform

2. Install dependencies
pip install -r requirements.txt

3. Initialize the database
python app.py init-db

4. Seed sample data (admin + demo products)
python app.py seed

5. Run the server
python app.py


Server will start at:
http://127.0.0.1:5000

🔑 Default Admin Account
Email	Password
admin@example.com	adminpass
📡 API Endpoints
Auth

POST /api/auth/register

POST /api/auth/login

Products

GET /api/products

GET /api/products/<id>

POST /api/products (admin)

PUT /api/products/<id> (admin)

DELETE /api/products/<id> (admin)

Cart / Orders

GET /api/cart

POST /api/cart/add

POST /api/cart/remove

POST /api/cart/checkout

Admin

GET /api/admin/orders

📁 Project Structure
/
├── app.py
├── requirements.txt
└── ecommerce.sqlite (generated after running)

📃 License

This project is released under the MIT License.

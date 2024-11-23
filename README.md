# API Gateway 🚪

A microservice serving as the single entry point for the application. It handles routing, authentication, and request validation before forwarding to other services.

Features

Routing: Directs API requests to the appropriate service (Orders or Events).
Authentication: Validates JWT tokens for all incoming requests.
Role-based Access Control: Enforces access permissions based on user roles.
Tech Stack

Node.js: Backend framework
JWT: Token-based authentication
API Endpoints

Method	Endpoint	Description
GET	/api/events	Fetch events via Events Service
POST	/api/orders	Forward order creation to Orders Service
POST	/api/login	Authenticate users
Environment Variables

JWT_SECRET: Secret key for token validation
RABBITMQ_URL: RabbitMQ connection string
SERVICE_URL_ORDERS: URL of the Orders Service
SERVICE_URL_EVENTS: URL of the Events Service
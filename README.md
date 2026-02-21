# Product Catalog

Sales catalog app for displaying inventory availability to buyers.

## Features

- **Product Display**: Visual catalog with images, colors, and quantities
- **Search & Filter**: Find products by style, color, or category
- **Multi-user**: Admin and sales rep roles
- **CSV Import**: Import data from Zoho Analytics exports
- **Mobile Friendly**: Works on tablets for in-person meetings

## Setup

1. Deploy to Railway from this GitHub repo
2. Add PostgreSQL database in Railway
3. Set environment variables (Railway does this automatically for DATABASE_URL)
4. Login with default admin credentials: `admin` / `admin123`
5. Change the admin password and add sales rep users

## CSV Import Format

Export from Zoho Analytics with these columns:
- Style Name (required)
- Color
- Commodity (category)
- Left to Sell (available quantity)
- On Hand
- Open Order
- To Come

## Environment Variables

- `DATABASE_URL` - PostgreSQL connection string (auto-set by Railway)
- `SESSION_SECRET` - Session encryption key (optional, has default)
- `PORT` - Server port (auto-set by Railway)
# Trigger deploy

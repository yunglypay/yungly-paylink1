# Yungly PayLink — MVP

Teen creator payment-link product. Black + white + lavender palette.

---

## Stack
- **Backend**: Node.js + Express (in-memory store — swap for PostgreSQL/Supabase in prod)
- **Payment**: Razorpay mock (drop in your real keys to go live)
- **Frontend**: Vanilla HTML/CSS/JS — zero framework dependencies

---

## Setup

```bash
cd backend
npm install
npm start
```

Then open → http://localhost:3000

---

## Screens

### Teen Creator
- Dashboard — wallet balance, monthly limit, recent links + earnings
- My PayLinks — create, copy, preview all links
- Earnings — full transaction history
- Profile — KYC status, limits, blocked categories

### Customer (public)
- Pay page at `/pay/:linkId`
- UPI / Card / Netbanking selector
- Mock payment → receipt + txn ID

### Guardian
- Overview — teen's spending vs limit, wallet
- Alerts — real-time notification for every payment
- Settings — per-link limit, daily/monthly limit

### Admin
- Platform stats — volume, users, success rate
- Users — all teen creators
- All Transactions — complete audit log

---

## Go live with Razorpay

1. Create account at https://razorpay.com
2. Get API keys from Dashboard → Settings → API Keys
3. In `backend/server.js`, update:
   ```js
   key: 'rzp_live_YourActualKey'
   ```
4. In `frontend/public/index.html`, add Razorpay checkout script:
   ```html
   <script src="https://checkout.razorpay.com/v1/checkout.js"></script>
   ```
5. In `initiatePayment()`, replace the mock with:
   ```js
   const rzp = new Razorpay({ key: orderData.key, ...orderData, handler: confirmPayment });
   rzp.open();
   ```
6. In `server.js` `/confirm` route, verify signature:
   ```js
   const generated = crypto.createHmac('sha256', 'YOUR_SECRET').update(orderId+'|'+paymentId).digest('hex');
   if (generated !== signature) return res.status(400).json({ error: 'Invalid payment' });
   ```

---

## Production checklist
- [ ] Replace in-memory store with PostgreSQL or Supabase
- [ ] Add JWT auth (replace demo login)
- [ ] Add Razorpay live keys + signature verification
- [ ] Add OTP/phone verification for onboarding
- [ ] Deploy backend to Railway / Render / AWS
- [ ] Point domain yunglypay.in to frontend

---

Built for Yungly Pay · Kerala, India
